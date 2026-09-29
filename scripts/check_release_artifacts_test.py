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

Ten of the cases exist because the first version of the gate did not fail on them.  A
reviewer put three of its four properties back to their 0.3.0 state while it went on
reporting all four satisfied, by mutating the *shape* of a check rather than its words: a
read-back whose `exit 1` is deleted still mentions everything the scan looked for, and a
tarball path assigned to a shell variable first carries no literal directory for it to find.
Those mutations are `..._not_compared`, `..._mismatch_not_fatal`, `..._via_variable` and
`..._exit_swallowed` below.  They are the reason the gate now reads block structure and
resolves assignments, and they are here rather than in a commit message because a property
nobody can re-break on demand is a claim, not a gate.

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

EXPECTED_CASES = 26


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


# ── The mutations the first version of the gate passed ─────────────────────────────────
#
# Each of these leaves every string the old scan looked for in place and removes only the
# part that makes the check do something.  A gate that passes one of them is asserting the
# vocabulary of the fix rather than the fix.


def case_install_name_readback_not_compared(root: Path) -> None:
    # The read-back becomes a log line. `otool -D` is still there and so is the expected
    # install name -- in the echo -- which is all the first version of the gate required.
    edit(
        root,
        RELEASE,
        '''            if [ "${got}" != "@rpath/libphantom_protocol.dylib" ]; then
              echo "install name is \'${got}\', expected \'@rpath/libphantom_protocol.dylib\'" >&2
              exit 1
            fi
''',
        '''            echo "install name is \'${got}\', want \'@rpath/libphantom_protocol.dylib\'"
''',
    )


def case_install_name_mismatch_not_fatal(root: Path) -> None:
    # The comparison survives; only the exit does not. A wrong install name is then
    # reported on stdout and shipped, which is 0.3.0's outcome with a diagnostic.
    edit(root, RELEASE, "              exit 1\n            fi", "            fi")


def case_packager_readback_not_compared(root: Path) -> None:
    edit(
        root,
        PACKAGER,
        '''    if [ "${got}" != "@rpath/libphantom_protocol.dylib" ]; then
        echo "install name is \'${got}\', expected \'@rpath/libphantom_protocol.dylib\'" >&2
        exit 1
    fi
''',
        '''    echo "install name is \'${got}\', want \'@rpath/libphantom_protocol.dylib\'"
''',
    )


def case_packager_mismatch_not_fatal(root: Path) -> None:
    edit(root, PACKAGER, "        exit 1\n    fi", "    fi")


def case_wasmtime_readback_not_compared(root: Path) -> None:
    edit(
        root,
        CROSS,
        '''          if [ "${got}" != "${want}" ]; then
            echo "installed wasmtime ${got}, expected ${want}" >&2
            exit 1
          fi
''',
        '''          echo "installed wasmtime ${got}, wanted ${want}"
''',
    )


def case_wasmtime_mismatch_not_fatal(root: Path) -> None:
    edit(root, CROSS, "            exit 1\n          fi", "          fi")


def case_checksum_directory_via_variable(root: Path) -> None:
    # The 0.3.0 defect exactly -- the digest line names `dist/<tarball>` -- written so that
    # no `.tar.gz` literal in the file carries a separator.
    edit(
        root,
        RELEASE,
        '''          ( cd dist && shasum -a 256 "${NAME}.tar.gz" > "${NAME}.tar.gz.sha256" )
          ( cd dist && shasum -a 256 -c "${NAME}.tar.gz.sha256" )''',
        '''          TGZ="dist/${NAME}.tar.gz"
          shasum -a 256 "${TGZ}" > "${TGZ}.sha256"
          shasum -a 256 -c "${TGZ}.sha256"''',
    )


def case_checksum_exit_swallowed(root: Path) -> None:
    # The verification runs and its verdict is discarded, which is the same as not running
    # it while looking like the fix.
    edit(
        root,
        RELEASE,
        '( cd dist && shasum -a 256 -c "${NAME}.tar.gz.sha256" )',
        '( cd dist && shasum -a 256 -c "${NAME}.tar.gz.sha256" ) || true',
    )


def case_library_staged_from_release_dir(root: Path) -> None:
    # LIBDIR still says `dist`, and the copy still succeeds: `cargo build --profile dist`
    # does not remove an earlier `target/<target>/release/` tree, so this ships the
    # stripped library from whatever built last.
    edit(
        root,
        RELEASE,
        'cp "${LIBDIR}/libphantom_protocol.rlib" "dist/${NAME}/"',
        'cp "target/${{ matrix.target }}/release/libphantom_protocol.rlib" "dist/${NAME}/"',
    )


def case_maturin_build_removed(root: Path) -> None:
    # The wheel job keeps its comments, its venv smoke test and its upload, and builds
    # nothing. The per-line check over `maturin build` lines then has no line to judge.
    drop_line(root, RELEASE, "maturin build --profile dist")


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
    # The ten the first version of the gate passed.
    (
        "install-name read-back reduced to a log line",
        "release.yml: reads the install name back with otool -D but never compares",
        case_install_name_readback_not_compared,
    ),
    (
        "install-name mismatch no longer fails the step",
        "release.yml: compares the install name it read back but no non-zero exit",
        case_install_name_mismatch_not_fatal,
    ),
    (
        "C bundle's read-back reduced to a log line",
        "package.sh: reads the install name back with otool -D but never compares",
        case_packager_readback_not_compared,
    ),
    (
        "C bundle's install-name mismatch no longer fails",
        "package.sh: compares the install name it read back but no non-zero exit",
        case_packager_mismatch_not_fatal,
    ),
    (
        "wasmtime read-back reduced to a log line",
        "never compares it against WASMTIME_VERSION",
        case_wasmtime_readback_not_compared,
    ),
    (
        "wasmtime mismatch no longer fails the job",
        "a run against an unpinned runtime is logged",
        case_wasmtime_mismatch_not_fatal,
    ),
    (
        "digest line carries dist/ through a shell variable",
        "expands to `dist/",
        case_checksum_directory_via_variable,
    ),
    (
        "digest verification's verdict discarded",
        "swallows its own exit status",
        case_checksum_exit_swallowed,
    ),
    (
        "library staged out of the stripped release/ tree",
        "stages a library out of a release/ directory",
        case_library_staged_from_release_dir,
    ),
    (
        "wheel job builds nothing at all",
        "mentions maturin but runs no",
        case_maturin_build_removed,
    ),
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
