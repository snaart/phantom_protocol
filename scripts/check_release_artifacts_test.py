#!/usr/bin/env python3
"""Cases for `scripts/check_release_artifacts.py`.

A gate over the release path can never be exercised by a release: tags happen once, and the
run that would have caught the defect is the one that shipped it.  So the only evidence that
this gate reads the files correctly is that it fails on a tree where the defect is back.

Each case copies the four files the gate reads, mutates exactly one of them into its 0.3.0
state, and requires a non-zero exit whose message names the property that broke.  The
unmutated copy has to pass first -- otherwise every case below would "fail" for the
uninteresting reason that the copy is not a faithful one -- and the case count is asserted,
because a harness that has quietly stopped mutating anything reports the same success as one
that checked everything.

Usage:  scripts/check_release_artifacts_test.py
Exit:   0 when every case behaves, 1 when one does not.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
GATE = REPO / "scripts" / "check_release_artifacts.py"

# Everything the gate reads. A file added to the gate and not to this list makes the cases
# fail on a missing file rather than pass silently.
FILES = [
    Path("Cargo.toml"),
    Path(".github/workflows/release.yml"),
    Path(".github/workflows/cross.yml"),
    Path("tests/bindings/c/package.sh"),
]

EXPECTED_CASES = 16


def stage() -> Path:
    root = Path(tempfile.mkdtemp(prefix="check-release-artifacts-"))
    for rel in FILES:
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(REPO / rel, root / rel)
    return root


def run(root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(GATE), "--repo-root", str(root)],
        capture_output=True,
        text=True,
        check=False,
    )


def edit(root: Path, rel: Path, old: str, new: str) -> None:
    path = root / rel
    text = path.read_text(encoding="utf-8")
    if text.count(old) != 1:
        raise SystemExit(
            f"case setup: {rel} contains {text.count(old)} copies of the text this case "
            f"mutates, expected exactly 1:\n  {old!r}"
        )
    path.write_text(text.replace(old, new), encoding="utf-8")


def drop_line(root: Path, rel: Path, needle: str) -> None:
    path = root / rel
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    kept = [ln for ln in lines if needle not in ln]
    if len(kept) == len(lines):
        raise SystemExit(f"case setup: no line of {rel} contains {needle!r}")
    path.write_text("".join(kept), encoding="utf-8")


MANIFEST = Path("Cargo.toml")
RELEASE = Path(".github/workflows/release.yml")
CROSS = Path(".github/workflows/cross.yml")
PACKAGER = Path("tests/bindings/c/package.sh")


def case_strip_symbols(root: Path) -> None:
    edit(root, MANIFEST, 'inherits = "release"\nstrip = "none"', 'inherits = "release"\nstrip = "symbols"')


def case_no_dist_profile(root: Path) -> None:
    text = (root / MANIFEST).read_text(encoding="utf-8")
    head, _, tail = text.partition("[profile.dist]")
    if not tail:
        raise SystemExit("case setup: Cargo.toml declares no [profile.dist]")
    _, _, rest = tail.partition("\n\n")
    (root / MANIFEST).write_text(head + rest, encoding="utf-8")


def case_release_profile_build(root: Path) -> None:
    edit(
        root,
        RELEASE,
        "cargo build --manifest-path core/Cargo.toml --profile dist --target",
        "cargo build --manifest-path core/Cargo.toml --release --target",
    )


def case_libdir_points_at_release(root: Path) -> None:
    edit(root, RELEASE, '/dist"\n          cp "${LIBDIR}', '/release"\n          cp "${LIBDIR}')


def case_no_install_name_rewrite(root: Path) -> None:
    drop_line(root, RELEASE, "install_name_tool -id @rpath")


def case_install_name_rewrite_commented_out(root: Path) -> None:
    # The defect's fix is described in a comment right beside the command that implements
    # it. A scan that matched the prose would pass this tree and ship the same broken
    # library.
    edit(
        root,
        RELEASE,
        "            install_name_tool -id @rpath/libphantom_protocol.dylib \\",
        "            # install_name_tool -id @rpath/libphantom_protocol.dylib \\",
    )


def case_no_install_name_readback(root: Path) -> None:
    drop_line(root, RELEASE, 'otool -D "dist/${NAME}/libphantom_protocol.dylib"')


def case_checksum_carries_directory(root: Path) -> None:
    edit(
        root,
        RELEASE,
        '( cd dist && shasum -a 256 "${NAME}.tar.gz" > "${NAME}.tar.gz.sha256" )',
        'shasum -a 256 "dist/${NAME}.tar.gz" > "dist/${NAME}.tar.gz.sha256"',
    )


def case_checksum_unverified(root: Path) -> None:
    drop_line(root, RELEASE, "shasum -a 256 -c")


def case_wasmtime_latest(root: Path) -> None:
    # Whatever the pin currently says, replaced by the moving name the installer defaults
    # to. The version itself is deliberately not written down here: a bump must not have
    # to touch these cases.
    path = root / CROSS
    text, n = re.subn(
        r"^(\s*WASMTIME_VERSION:).*$", r"\1 latest", path.read_text(encoding="utf-8"), count=1, flags=re.MULTILINE
    )
    if n != 1:
        raise SystemExit("case setup: cross.yml declares no WASMTIME_VERSION")
    path.write_text(text, encoding="utf-8")


def case_wasmtime_unset(root: Path) -> None:
    drop_line(root, CROSS, "WASMTIME_VERSION: v")


def case_wasmtime_version_flag_dropped(root: Path) -> None:
    edit(
        root,
        CROSS,
        'curl -sSf https://wasmtime.dev/install.sh | bash -s -- \\\n            --version "${WASMTIME_VERSION}"',
        "curl -sSf https://wasmtime.dev/install.sh | bash",
    )


def case_wasmtime_not_read_back(root: Path) -> None:
    drop_line(root, CROSS, 'want="${WASMTIME_VERSION#v}"')


def case_packager_no_install_name(root: Path) -> None:
    drop_line(root, PACKAGER, "install_name_tool -id @rpath")


def case_packager_release_profile(root: Path) -> None:
    edit(
        root,
        PACKAGER,
        'cargo build --profile dist --manifest-path "${REPO_ROOT}/core/Cargo.toml"',
        'cargo build --release --manifest-path "${REPO_ROOT}/core/Cargo.toml"',
    )


def case_wheel_release_profile(root: Path) -> None:
    edit(root, RELEASE, "maturin build --profile dist", "maturin build --release")


CASES = [
    ("the shipped profile strips symbols again", "strip", case_strip_symbols),
    ("no [profile.dist] at all", "no [profile.dist]", case_no_dist_profile),
    ("artifacts built --release", "does not build --profile dist", case_release_profile_build),
    ("Package reads target/<target>/release", "target/<target>/dist", case_libdir_points_at_release),
    ("no install-name rewrite", "install name", case_no_install_name_rewrite),
    (
        "install-name rewrite left as a comment",
        "install name",
        case_install_name_rewrite_commented_out,
    ),
    ("install name never read back", "otool -D", case_no_install_name_readback),
    (
        "digest line carries the dist/ prefix",
        "directory into the digest line",
        case_checksum_carries_directory,
    ),
    ("digest never verified", "nothing verifies the digest", case_checksum_unverified),
    ("wasmtime pinned to a moving name", "not an exact", case_wasmtime_latest),
    ("no wasmtime version at all", "no WASMTIME_VERSION", case_wasmtime_unset),
    (
        "installer given no --version",
        "does not pass --version",
        case_wasmtime_version_flag_dropped,
    ),
    (
        "installed wasmtime never read back",
        "reads the installed wasmtime version back",
        case_wasmtime_not_read_back,
    ),
    ("C bundle keeps the runner's install name", "install name", case_packager_no_install_name),
    ("C bundle built --release", "does not build --profile dist", case_packager_release_profile),
    ("Python wheel built --release", "does not build --profile dist", case_wheel_release_profile),
]


def main() -> int:
    failures: list[str] = []

    baseline = stage()
    try:
        got = run(baseline)
        if got.returncode != 0:
            failures.append(
                "the unmutated copy of the tree does not pass; every case below is "
                f"meaningless until it does\n{got.stdout}{got.stderr}"
            )
    finally:
        shutil.rmtree(baseline, ignore_errors=True)

    if len(CASES) != EXPECTED_CASES:
        failures.append(
            f"the harness holds {len(CASES)} cases, EXPECTED_CASES says {EXPECTED_CASES}; "
            "a case that stopped being run reports the same success as one that passed"
        )

    for name, fragment, mutate in CASES:
        root = stage()
        try:
            mutate(root)
            got = run(root)
            if got.returncode == 0:
                failures.append(f"{name}: the gate passed a tree that would ship the defect")
                continue
            if fragment not in got.stderr:
                failures.append(
                    f"{name}: the gate failed, but no message mentions {fragment!r}; it may "
                    f"be failing for another reason\n{got.stderr}"
                )
                continue
            print(f"  ok  {name}")
        finally:
            shutil.rmtree(root, ignore_errors=True)

    if failures:
        print("\ncheck-release-artifacts cases FAILED", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return 1

    print(f"check-release-artifacts: {len(CASES)} cases, the unmutated tree passes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
