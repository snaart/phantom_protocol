#!/usr/bin/env python3
"""Keep the release workflow from shipping a library nobody can use.

Every defect this script checks for shipped in 0.3.0, was green in CI, and was found by
downloading the published tarball -- because nothing in the tree looks at the artifact
after it is built.  A release runs once per tag, on a runner, and the four properties
below are invisible on the machine that produced them:

  1. **The shipped library keeps its symbol table.**  `uniffi-bindgen --library` reads the
     interface out of the cdylib's `UNIFFI_META_*` symbols, and
     `[profile.release] strip = "symbols"` removes them.  The stripped Linux `.so` still
     carries the metadata *strings* in `.rodata`, so nothing about the file looks empty,
     and the generator reports "No UniFFI metadata found" -- and exits 0 while writing no
     bindings at all.  The release artifacts therefore build with `[profile.dist]`, which
     inherits every optimisation setting from `release` and keeps the table.

  2. **The macOS libraries are relocatable.**  rustc writes the absolute path of the build
     directory into a Mach-O library's install name, so an unedited artifact expects to be
     found under `/Users/runner/work/...`.  Every consumer that links it dies before
     `main` with `dyld: Library not loaded`, naming a directory that exists only on the
     runner.  The Package step rewrites the name to `@rpath/libphantom_protocol.dylib` and
     reads it back, because a rewrite that silently did nothing looks exactly like one
     that worked.

  3. **The `.sha256` files verify where they are downloaded.**  `shasum -c` re-reads the
     path stored in the digest line, so hashing `dist/x.tar.gz` produces a file that
     verifies only for someone who reproduced the `dist/` directory.  The two files are
     published side by side; the digest must name the tarball by its basename.

  4. **The WASI runtime is pinned.**  The wasmtime installer resolves the latest release
     unless it is given `--version`, so the runtime the WASI tests run against used to
     change with no change to the tree, under a comment that said "pinned".  That is how
     wasmtime 49 arrived unannounced during the 0.3.0 release.  The version is one env
     line and the job reads back what got installed.

The workflows cannot test themselves -- a release happens on a tag, once -- so this is the
regression test for all four: a text scan over the files that decide what is shipped.  Its
own cases live in `scripts/check_release_artifacts_test.sh`, which mutates each property
back to its 0.3.0 state and requires this script to fail.

Usage:  scripts/check_release_artifacts.py [--repo-root DIR]
Exit:   0 when every property holds, 1 when one does not, 2 on bad input.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

RELEASE_WORKFLOW = Path(".github/workflows/release.yml")
CROSS_WORKFLOW = Path(".github/workflows/cross.yml")
ROOT_MANIFEST = Path("Cargo.toml")
C_PACKAGER = Path("tests/bindings/c/package.sh")

# The profile the shipped artifacts are built with, and the install name a redistributable
# macOS library has to carry.
SHIP_PROFILE = "dist"
INSTALL_NAME = "@rpath/libphantom_protocol.dylib"


def read(root: Path, rel: Path) -> str:
    path = root / rel
    if not path.is_file():
        raise SystemExit(f"check-release-artifacts: {rel} is missing from {root}")
    return path.read_text(encoding="utf-8")


def strip_comments(text: str) -> str:
    """Drop `#` comment lines, so prose about a defect never satisfies a check.

    Every one of these properties is described in a comment next to the code that
    implements it.  Matching the comment instead of the command is the one way a scan like
    this passes a tree that would still ship the broken artifact.
    """
    return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))


def profile_block(manifest: str, name: str) -> str | None:
    """Return the body of `[profile.<name>]`, or None when it is not declared."""
    m = re.search(
        rf"^\[profile\.{re.escape(name)}\]\s*$(.*?)(?=^\[|\Z)",
        manifest,
        re.MULTILINE | re.DOTALL,
    )
    return None if m is None else m.group(1)


def setting(block: str, key: str) -> str | None:
    m = re.search(rf"^\s*{re.escape(key)}\s*=\s*(\S+)", block, re.MULTILINE)
    return None if m is None else m.group(1).strip().strip('"')


def check_unstripped(root: Path, problems: list[str]) -> None:
    manifest = read(root, ROOT_MANIFEST)
    body = profile_block(manifest, SHIP_PROFILE)
    if body is None:
        problems.append(
            f"  {ROOT_MANIFEST}: no [profile.{SHIP_PROFILE}]; the release workflow builds "
            f"with --profile {SHIP_PROFILE}"
        )
    else:
        if setting(body, "inherits") != "release":
            problems.append(
                f"  {ROOT_MANIFEST}: [profile.{SHIP_PROFILE}] must inherit release, so the "
                "shipped library keeps every optimisation setting"
            )
        strip = setting(body, "strip")
        if strip != "none":
            has = "declares no strip setting" if strip is None else f"has strip = {strip!r}"
            problems.append(
                f"  {ROOT_MANIFEST}: [profile.{SHIP_PROFILE}] {has}, and inherits "
                '`strip = "symbols"` from release unless it says `strip = "none"` -- '
                "uniffi-bindgen --library reads UNIFFI_META_* out of the symbol table and "
                "finds nothing without it"
            )

    release = strip_comments(read(root, RELEASE_WORKFLOW))
    # Command lines only: a step's `- name:` is prose about the command, and reporting it
    # beside the command says the same thing twice.
    builds = [
        ln.strip()
        for ln in release.splitlines()
        if "cargo build" in ln and not ln.strip().startswith("- name:")
    ]
    if not builds:
        problems.append(f"  {RELEASE_WORKFLOW}: no cargo build step; what is shipped?")
    for line in builds:
        if f"--profile {SHIP_PROFILE}" not in line:
            problems.append(
                f"  {RELEASE_WORKFLOW}: `{line}` does not build --profile {SHIP_PROFILE}; a "
                "--release artifact is stripped and generates no bindings"
            )
    if not re.search(
        rf'LIBDIR="target/\$\{{\{{\s*matrix\.target\s*\}}\}}/{SHIP_PROFILE}"', release
    ):
        problems.append(
            f"  {RELEASE_WORKFLOW}: the Package step does not read from "
            f"target/<target>/{SHIP_PROFILE}/; cargo names the directory after the profile, "
            "so this and the build command have to agree"
        )

    # maturin compiles the library and then runs uniffi-bindgen against it, so the wheel
    # job does not ship a broken artifact when the library is stripped -- it fails, having
    # written a `.whl` with no `.dist-info` in it.
    for line in [ln.strip() for ln in release.splitlines() if "maturin build" in ln]:
        if f"--profile {SHIP_PROFILE}" not in line:
            problems.append(
                f"  {RELEASE_WORKFLOW}: `{line}` does not build --profile {SHIP_PROFILE}; "
                "maturin generates the wheel's Python module out of the library it just "
                "compiled, and a stripped one ends the build with nothing installable"
            )

    packager = strip_comments(read(root, C_PACKAGER))
    if f"--profile {SHIP_PROFILE}" not in packager:
        problems.append(
            f"  {C_PACKAGER}: does not build --profile {SHIP_PROFILE}; the C bundle ships a "
            "library too"
        )
    if f"target/{SHIP_PROFILE}/libphantom_protocol" not in packager:
        problems.append(
            f"  {C_PACKAGER}: does not stage the library from target/{SHIP_PROFILE}/"
        )


def check_install_name(root: Path, problems: list[str]) -> None:
    for rel in (RELEASE_WORKFLOW, C_PACKAGER):
        text = strip_comments(read(root, rel))
        if not re.search(rf"install_name_tool\s+-id\s+{re.escape(INSTALL_NAME)}", text):
            problems.append(
                f"  {rel}: does not rewrite the macOS install name to {INSTALL_NAME}; rustc "
                "records the build directory's absolute path and every consumer that links "
                "the shipped dylib dies at launch with `dyld: Library not loaded`"
            )
        if "otool -D" not in text or INSTALL_NAME not in text.replace(
            "install_name_tool -id " + INSTALL_NAME, ""
        ):
            problems.append(
                f"  {rel}: does not read the install name back with otool -D and compare it "
                f"against {INSTALL_NAME}; a rewrite that did nothing looks like one that "
                "worked"
            )


def check_checksums(root: Path, problems: list[str]) -> None:
    release = strip_comments(read(root, RELEASE_WORKFLOW))
    calls = re.findall(r"shasum[^\n]*", release)
    if not calls:
        problems.append(
            f"  {RELEASE_WORKFLOW}: nothing computes a checksum for the published tarballs"
        )
    for call in calls:
        for token in re.findall(r'"?\$?\{?[^\s"\']*\.tar\.gz(?:\.sha256)?"?', call):
            name = token.strip('"')
            if "/" in name:
                problems.append(
                    f"  {RELEASE_WORKFLOW}: `{call.strip()}` names {name}, which puts a "
                    "directory into the digest line; `shasum -c` then fails for everyone "
                    "who downloaded the tarball and its .sha256 side by side"
                )
    if not re.search(r"shasum\s+-a\s+256\s+-c\b", release):
        problems.append(
            f"  {RELEASE_WORKFLOW}: nothing verifies the digest it just wrote; the check "
            "costs a millisecond and is the only thing that would have caught the prefix"
        )


def check_wasmtime_pin(root: Path, problems: list[str]) -> None:
    text = read(root, CROSS_WORKFLOW)
    pin = re.search(r"^\s*WASMTIME_VERSION:\s*(\S+)[^\S\n]*(?:#[^\n]*)?$", text, re.MULTILINE)
    if pin is None:
        problems.append(
            f"  {CROSS_WORKFLOW}: no WASMTIME_VERSION; the installer then resolves whatever "
            "was released last and the WASI tests run against a runtime the tree never named"
        )
    elif not re.fullmatch(r"v\d+\.\d+\.\d+", pin.group(1)):
        problems.append(
            f"  {CROSS_WORKFLOW}: WASMTIME_VERSION is {pin.group(1)!r}, which is not an exact "
            "vMAJOR.MINOR.PATCH release tag"
        )

    body = strip_comments(text)
    installs = [ln for ln in body.splitlines() if "install.sh" in ln and "wasmtime" in ln]
    if not installs:
        problems.append(f"  {CROSS_WORKFLOW}: nothing installs wasmtime")
    # The flag and the version reference may be split across a continued line, so look at
    # the installer invocation together with the two lines after it.
    lines = body.splitlines()
    for ln in installs:
        i = lines.index(ln)
        window = " ".join(lines[i : i + 3])
        if "--version" not in window or "WASMTIME_VERSION" not in window:
            problems.append(
                f"  {CROSS_WORKFLOW}: `{ln.strip()}` does not pass --version "
                '"${WASMTIME_VERSION}"; the installer defaults to the latest release'
            )
    if not re.search(r"wasmtime[\"']?\s+--version", body) or "WASMTIME_VERSION#v" not in body:
        problems.append(
            f"  {CROSS_WORKFLOW}: nothing reads the installed wasmtime version back and "
            "compares it against WASMTIME_VERSION; an argument the installer ignores leaves "
            "the pin looking honoured"
        )


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--repo-root",
        default=Path(__file__).resolve().parent.parent,
        type=Path,
        help="repository root to check (default: the one holding this script)",
    )
    args = ap.parse_args()
    root: Path = args.repo_root
    if not root.is_dir():
        print(f"check-release-artifacts: {root} is not a directory", file=sys.stderr)
        return 2

    problems: list[str] = []
    check_unstripped(root, problems)
    check_install_name(root, problems)
    check_checksums(root, problems)
    check_wasmtime_pin(root, problems)

    if problems:
        print(
            "check-release-artifacts: the release path would ship an artifact a consumer "
            "cannot use",
            file=sys.stderr,
        )
        for p in problems:
            print(p, file=sys.stderr)
        return 1

    print(
        "check-release-artifacts: shipped library unstripped, macOS install name relocatable, "
        "checksums verify in place, WASI runtime pinned"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
