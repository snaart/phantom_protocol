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
own cases live in `scripts/check_release_artifacts_test.py`, which mutates each property
back to its 0.3.0 state and requires this script to fail.

WHAT THE FIRST VERSION OF THIS SCRIPT DID NOT ASSERT.  Three of the four properties could
be put back to their 0.3.0 state while this script still printed all four as satisfied,
because each was checked by looking for a string rather than for the thing the string is
supposed to do:

  * Both install-name read-backs and the wasmtime read-back were satisfied by the presence
    of `otool -D` / `wasmtime --version` and a second mention of the expected value.  An
    `echo` mentioning it counts as a mention, so deleting the `exit 1` -- turning the
    read-back into a log line that reports the wrong install name and ships it anyway --
    changed nothing here.  A read-back is now only accepted when a `!=` comparison against
    the expected value is followed, within the same block, by a non-zero `exit`.

  * The digest's basename requirement was a scan for `.tar.gz` literals carrying a `/`.
    Assigning the path to a shell variable first (`TGZ="dist/${NAME}.tar.gz"`;
    `shasum -a 256 "${TGZ}"`) reproduced the exact 0.3.0 defect with no literal to find.
    Shell assignments in the same file are now resolved before the argument is judged, and
    every argument is judged, not only the ones that spell out a tarball name.

Those two rules are why this script reads assignments and block structure rather than
single lines.  What it still cannot see is anything a step computes at run time -- a path
built from a command substitution is opaque here, and the read-back inside the job is what
covers it.  Each of the strengthened checks has a case in the test harness that mutates
the file exactly the way the reviewer did.

Usage:  scripts/check_release_artifacts.py [--repo-root DIR]
Exit:   0 when every property holds, 1 when one does not, 2 on bad input.
"""

from __future__ import annotations

import argparse
import re
import shlex
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

# `exit 1` and friends. `exit 0` deliberately does not match: a read-back that ends the
# step successfully is the defect, not the fix.
NONZERO_EXIT = re.compile(r"\bexit\s+[1-9][0-9]*\b")

# `${NAME}` / `$NAME`. `${{ matrix.target }}` does not match (the character after `${` is
# not an identifier start) and neither does `${VAR#v}`, which is what keeps the expansion
# below from pretending to understand shell it does not.
VAR_REF = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)\b")

ASSIGNMENT = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$")

# A value this scan cannot resolve -- a command substitution, in practice. Marked rather
# than dropped so an argument built out of one is never mistaken for a bare basename.
OPAQUE = "\x00"


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


def shell_assignments(body: str) -> dict[str, str]:
    """Collect `VAR=value` assignments out of a comment-stripped shell body.

    A value holding a command substitution is recorded as OPAQUE: this scan cannot know
    what it expands to, and pretending it expands to nothing would let a path hide inside
    one.  Everything else is kept verbatim, references and all, for `expand` to resolve.
    """
    env: dict[str, str] = {}
    for raw in body.splitlines():
        m = ASSIGNMENT.match(raw.strip())
        if m is None:
            continue
        name, value = m.group(1), m.group(2).strip()
        if "$(" in value or "`" in value:
            env[name] = OPAQUE
            continue
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        env[name] = value
    return env


def expand(value: str, env: dict[str, str], rounds: int = 4) -> str:
    """Resolve `${VAR}` / `$VAR` against `env`, leaving unknown names alone."""
    for _ in range(rounds):
        def one(m: re.Match[str]) -> str:
            name = m.group(1) or m.group(2)
            return env.get(name, m.group(0))

        grown = VAR_REF.sub(one, value)
        if grown == value:
            break
        value = grown
    return value


def enforced_readback(
    body: str,
    anchor: re.Pattern[str],
    compared_with: tuple[str, ...],
    context: tuple[str, ...] = (),
    window: int = 8,
) -> tuple[bool, bool, bool]:
    """Judge a read-back-and-compare block.

    `anchor` matches the line that reads a value back off the artifact.  Within the next
    `window` lines there has to be a `!=` comparison naming everything in `compared_with`,
    every string in `context` has to appear, and a non-zero `exit` has to come *after* the
    comparison.  Returns `(found, compared, enforced)`.

    The ordering requirement is the point: a block that reads the value, prints it, and
    carries on has all the same words in it as one that fails the job, and only the exit
    tells them apart.  That is precisely how the first version of this gate could be
    satisfied by a tree that shipped the 0.3.0 artifact.
    """
    lines = body.splitlines()
    found = compared = enforced = False
    for i, line in enumerate(lines):
        if not anchor.search(line):
            continue
        found = True
        block = lines[i : i + window]
        if not all(token in "\n".join(block) for token in context):
            continue
        at = next(
            (
                j
                for j, seg in enumerate(block)
                if "!=" in seg and all(token in seg for token in compared_with)
            ),
            None,
        )
        if at is None:
            continue
        compared = True
        if any(NONZERO_EXIT.search(seg) for seg in block[at + 1 :]):
            enforced = True
            break
    return found, compared, enforced


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
    # Staging the library from a hard-coded `release/` directory ships the stripped one no
    # matter what LIBDIR says, and the copy would still succeed: `cargo build --profile
    # dist` leaves an earlier `target/<target>/release/` tree untouched.
    for line in release.splitlines():
        if "libphantom_protocol" in line and "/release/" in line:
            problems.append(
                f"  {RELEASE_WORKFLOW}: `{line.strip()}` stages a library out of a "
                f"release/ directory; the shipped one is built into {SHIP_PROFILE}/ and the "
                "release tree may still hold a stripped library from an earlier build"
            )

    # maturin compiles the library and then runs uniffi-bindgen against it, so the wheel
    # job does not ship a broken artifact when the library is stripped -- it fails, having
    # written a `.whl` with no `.dist-info` in it.  Checked only for the lines that exist,
    # so the assertion has to be that a workflow mentioning maturin at all runs one.
    maturin_builds = [ln.strip() for ln in release.splitlines() if "maturin build" in ln]
    if "maturin" in release and not maturin_builds:
        problems.append(
            f"  {RELEASE_WORKFLOW}: mentions maturin but runs no `maturin build`; the wheel "
            "job's own build is what proves the shipped library still generates bindings"
        )
    for line in maturin_builds:
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
        found, compared, enforced = enforced_readback(
            text,
            re.compile(r"otool\s+-D"),
            compared_with=("!=", INSTALL_NAME),
        )
        if not found:
            problems.append(
                f"  {rel}: does not read the install name back with otool -D; a rewrite "
                "that did nothing looks like one that worked"
            )
        elif not compared:
            problems.append(
                f"  {rel}: reads the install name back with otool -D but never compares it "
                f"against {INSTALL_NAME}"
            )
        elif not enforced:
            problems.append(
                f"  {rel}: compares the install name it read back but no non-zero exit "
                "follows, so a wrong install name is logged and then shipped; the read-back "
                "has to fail the step"
            )


def digest_arguments(call: str) -> list[str]:
    """The path-shaped arguments of a shasum invocation, flags and operators removed."""
    try:
        words = shlex.split(call, posix=True)
    except ValueError:
        # Unbalanced quoting across a continued line -- fall back to whitespace splitting
        # rather than reporting nothing, which is the vacuous answer.
        words = [w.strip("\"'") for w in call.split()]
    skip = {"(", ")", "{", "}", "&&", "||", ";", ">", ">>", "|", "cd", "shasum", "then", "fi"}
    out: list[str] = []
    for word in words:
        cleaned = word.lstrip(">")
        if not cleaned or cleaned in skip or cleaned.startswith("-") or cleaned.isdigit():
            continue
        out.append(cleaned)
    return out


def check_checksums(root: Path, problems: list[str]) -> None:
    release = strip_comments(read(root, RELEASE_WORKFLOW))
    env = shell_assignments(release)
    calls = re.findall(r"shasum[^\n]*", release)
    if not calls:
        problems.append(
            f"  {RELEASE_WORKFLOW}: nothing computes a checksum for the published tarballs"
        )
    for call in calls:
        if "||" in call:
            problems.append(
                f"  {RELEASE_WORKFLOW}: `{call.strip()}` swallows its own exit status; a "
                "digest that could not be written or could not be verified has to fail the "
                "release"
            )
        for argument in digest_arguments(call):
            resolved = expand(argument, env)
            if "/" not in resolved:
                continue
            via = "" if resolved == argument else f" (`{argument}` expands to `{resolved}`)"
            problems.append(
                f"  {RELEASE_WORKFLOW}: `{call.strip()}` names {resolved}{via}, which puts a "
                "directory into the digest line; `shasum -c` then fails for everyone who "
                "downloaded the tarball and its .sha256 side by side"
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
    found, compared, enforced = enforced_readback(
        body,
        re.compile(r"wasmtime[\"']?\s+--version"),
        compared_with=("!=",),
        context=("WASMTIME_VERSION#v",),
    )
    if not found:
        problems.append(
            f"  {CROSS_WORKFLOW}: nothing reads the installed wasmtime version back; an "
            "argument the installer ignores leaves the pin looking honoured"
        )
    elif not compared:
        problems.append(
            f"  {CROSS_WORKFLOW}: reads the installed wasmtime version back but never "
            "compares it against WASMTIME_VERSION"
        )
    elif not enforced:
        problems.append(
            f"  {CROSS_WORKFLOW}: compares the installed wasmtime version against the pin "
            "but no non-zero exit follows, so a run against an unpinned runtime is logged "
            "and then treated as a pass"
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
