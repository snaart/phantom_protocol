#!/usr/bin/env python3
"""Which CI jobs are required to pass before `main` moves, and which are not.

A workflow job that is not a branch-protection context is advice.  It runs, it goes red, and
the merge button stays green -- and nothing anywhere in the tree says so, because the required
set lives in the repository's settings and not in a file anybody reviews.  That is how this
release's own `release artifact shape` job arrived: added to `ci.yml` in a change whose notes
say "branch-protection contexts are what make them count", and not required.  Seven older
`ci.yml` jobs were in the same state, among them `cargo package` (the one job that builds the
crate the way crates.io does), `cargo check (MSRV 1.93)`, and three gates whose whole purpose
is to fail.

This script derives the set that *should* be required from the workflow files, reads the set
that *is* required, and prints the difference plus the one command that closes it.  Deriving
rather than listing is deliberate: a list in a file goes stale the next time a job is added,
which is the defect, written down.

    scripts/required_status_checks.py                # default: report, change nothing
    scripts/required_status_checks.py --apply        # write the setting (needs admin rights)
    scripts/required_status_checks.py --repo OWNER/NAME --branch main

Reading the live set needs `gh` authenticated with rights over the repository's settings;
without it the script still prints the derived set and the command, which is the part a
maintainer needs.  Applying is a repository-settings change and belongs to whoever owns them.

WHAT IS REQUIRED.  Every job of every workflow that runs on `pull_request`, because a job
that runs on a pull request and cannot block it is a job whose result nobody has to read.
Matrix jobs are expanded, since each row is its own context.

WHAT IS NOT, AND WHY.  Three kinds, listed in EXCLUDED_WORKFLOWS and decided per job below:

  * Jobs that never run on a pull request -- the tag-triggered release pipeline and the
    `workflow_dispatch`-only wheel smoke test.  Requiring a context that never reports blocks
    every merge forever, which is why GitHub treats a missing context as pending.
  * `bench.yml`, which compares medians on a shared runner: a 2x threshold on a noisy
    measurement fails honest changes, so its verdict is read rather than enforced.
  * `fuzz.yml`, which is a 60-second-per-target search on PRs.  A crash it finds is a bug to
    triage with the artifact it uploaded; a search that found nothing in a minute is not
    evidence, and requiring it would mean re-running a coin toss to merge.

`integration`'s display name is `tcp + kcp loopback integration` and the "kcp" in it is
stale -- the job runs the TCP and PhantomUDP suites.  It is a pinned required context, so the
name must not be corrected: renaming it makes the required context unreportable and every
merge waits for a job that will never check in under that name again.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

import yaml

WORKFLOW_DIR = Path(".github/workflows")

# Whole workflows whose jobs are deliberately advisory. The reason is carried here because it
# is the only place anyone will look for it.
EXCLUDED_WORKFLOWS = {
    "bench.yml": (
        "medians on a shared runner; a 2x threshold on a noisy measurement fails honest "
        "changes, so the comparison is read rather than enforced"
    ),
    "fuzz.yml": (
        "a 60-second search per target; a crash is a bug to triage from the uploaded "
        "artifact, and a minute that found nothing is not evidence to gate a merge on"
    ),
}

# `if:` expressions that mean "this job does not run on a pull request".
NEVER_ON_PR = (
    "startsWith(github.ref, 'refs/tags/v')",
    "github.event_name == 'workflow_dispatch'",
)

MATRIX_REF = re.compile(r"\$\{\{\s*([^}]+?)\s*\}\}")


def load(path: Path) -> dict:
    with path.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def triggers(workflow: dict) -> list[str]:
    # PyYAML resolves the bare key `on` to the boolean True.
    raw = workflow.get("on", workflow.get(True)) or {}
    if isinstance(raw, str):
        return [raw]
    if isinstance(raw, list):
        return list(raw)
    return list(raw)


def matrix_rows(job: dict) -> list[dict]:
    """Expand a job's matrix into one dict per context, or `[{}]` when it has none."""
    matrix = (job.get("strategy") or {}).get("matrix")
    if not matrix:
        return [{}]
    rows: list[dict] = []
    for entry in matrix.get("include", []) or []:
        rows.append(dict(entry))
    axes = {k: v for k, v in matrix.items() if k not in ("include", "exclude")}
    if axes:
        combos: list[dict] = [{}]
        for key, values in axes.items():
            values = values if isinstance(values, list) else [values]
            combos = [dict(c, **{key: v}) for c in combos for v in values]
        # `include` entries that only add keys to an existing combination are not modelled:
        # no workflow here mixes the two forms, and guessing would invent context names.
        rows = combos + [r for r in rows if not any(set(r) >= set(c) for c in combos)]
    return rows or [{}]


def resolve(name: str, row: dict) -> str:
    """Substitute `${{ matrix.key }}` and `${{ matrix.a || matrix.b }}` in a job name."""

    def one(m: re.Match[str]) -> str:
        expr = m.group(1)
        for alternative in [part.strip() for part in expr.split("||")]:
            if not alternative.startswith("matrix."):
                continue
            value = row.get(alternative[len("matrix.") :])
            if value not in (None, "", False):
                return str(value)
        return m.group(0)

    return MATRIX_REF.sub(one, name)


def derive(root: Path) -> tuple[list[str], list[tuple[str, str]]]:
    """Return (contexts that should be required, [(context or job, why it is not)])."""
    required: list[str] = []
    advisory: list[tuple[str, str]] = []
    for path in sorted((root / WORKFLOW_DIR).glob("*.yml")):
        workflow = load(path)
        rel = path.name
        on = triggers(workflow)
        if "pull_request" not in on:
            for jid, job in (workflow.get("jobs") or {}).items():
                advisory.append((f"{rel}:{jid}", "the workflow does not run on a pull request"))
            continue
        for jid, job in (workflow.get("jobs") or {}).items():
            name = job.get("name", jid)
            condition = str(job.get("if", ""))
            if rel in EXCLUDED_WORKFLOWS:
                advisory.append((f"{rel}:{jid}", EXCLUDED_WORKFLOWS[rel]))
                continue
            if any(marker in condition for marker in NEVER_ON_PR):
                advisory.append((f"{rel}:{jid}", "never runs on a pull request"))
                continue
            for row in matrix_rows(job):
                resolved = resolve(name, row)
                if "${{" in resolved:
                    raise SystemExit(
                        f"required-status-checks: cannot resolve the context name for "
                        f"{rel}:{jid} -- {resolved!r}; teach `resolve` the expression it uses "
                        "rather than reporting a name GitHub will never send"
                    )
                required.append(resolved)
    return sorted(set(required)), advisory


def live(repo: str, branch: str) -> list[str] | None:
    try:
        out = subprocess.run(
            [
                "gh",
                "api",
                f"repos/{repo}/branches/{branch}/protection/required_status_checks",
                "--jq",
                ".contexts",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        return None
    if out.returncode != 0:
        return None
    try:
        contexts = json.loads(out.stdout)
    except json.JSONDecodeError:
        return None
    return sorted(contexts) if isinstance(contexts, list) else None


def default_repo() -> str:
    out = subprocess.run(
        ["gh", "repo", "view", "--json", "nameWithOwner", "--jq", ".nameWithOwner"],
        capture_output=True,
        text=True,
        check=False,
    )
    return out.stdout.strip() if out.returncode == 0 and out.stdout.strip() else "OWNER/REPO"


def patch_command(repo: str, branch: str, contexts: list[str]) -> str:
    """The one command that sets the required set, with every context spelled out.

    `PATCH .../protection/required_status_checks` replaces `contexts` wholesale, so the list
    has to be complete: a call naming only what is missing drops everything else.
    """
    fields = " \\\n  ".join(f"-f 'contexts[]={c}'" for c in contexts)
    return (
        f"gh api --method PATCH \\\n"
        f"  repos/{repo}/branches/{branch}/protection/required_status_checks \\\n"
        f"  -H 'Accept: application/vnd.github+json' \\\n"
        f"  -F 'strict=true' \\\n"
        f"  {fields}"
    )


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repo", default=None, help="OWNER/NAME (default: the checkout's remote)")
    ap.add_argument("--branch", default="main")
    ap.add_argument(
        "--repo-root",
        default=Path(__file__).resolve().parent.parent,
        type=Path,
        help="repository root holding .github/workflows (default: the one holding this script)",
    )
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument(
        "--dry-run",
        action="store_true",
        default=True,
        help="report and change nothing (the default)",
    )
    mode.add_argument(
        "--apply",
        action="store_true",
        help="set the required contexts; a repository-settings change, admin rights needed",
    )
    args = ap.parse_args()

    root: Path = args.repo_root
    if not (root / WORKFLOW_DIR).is_dir():
        print(f"required-status-checks: no {WORKFLOW_DIR} under {root}", file=sys.stderr)
        return 2

    repo = args.repo or default_repo()
    should, advisory = derive(root)

    print(f"# {len(should)} contexts should be required on {repo}@{args.branch}")
    current = live(repo, args.branch)
    if current is None:
        print("# (could not read the live setting; listing the derived set only)")
        missing = should
        extra: list[str] = []
    else:
        missing = [c for c in should if c not in current]
        extra = [c for c in current if c not in should]

    for context in should:
        mark = " " if current is not None and context in current else "+"
        print(f"{mark} {context}")

    if advisory:
        print("\n# deliberately not required:")
        for what, why in advisory:
            print(f"  - {what}: {why}")

    if extra:
        print(
            "\n# required but derived from no pull-request job -- a context nothing reports "
            "leaves every merge pending:"
        )
        for context in extra:
            print(f"  - {context}")

    if not missing and current is not None:
        print("\nrequired-status-checks: every pull-request job is a required context")
        return 0

    print(f"\n# {len(missing)} missing:")
    for context in missing:
        print(f"  - {context}")
    command = patch_command(repo, args.branch, should)
    print("\n# the whole set, in one call (PATCH replaces `contexts`, so it must be complete):")
    print(command)

    if args.apply:
        print("\n# applying", file=sys.stderr)
        done = subprocess.run(["bash", "-c", command], check=False)
        return done.returncode
    print(
        "\nrequired-status-checks: reported only; run with --apply, or paste the command "
        "above, to change the setting"
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
