//! Stamps the build's git identity into both binaries.
//!
//! A run artifact has to answer "which code produced this" for two hosts at
//! once, and asking git at *run* time cannot: the probe is normally started
//! from a results directory that is not a checkout, and the daemon runs from a
//! binary copied onto a VPS that has no repository at all. Resolving the commit
//! here — where the source actually is — and baking it in is the only place the
//! question has an answer.
//!
//! A source tarball with no git available is a normal case, not a failure: the
//! build proceeds and the identity reads `unknown`, which is honest and lets the
//! analysis say so rather than silently comparing two unlabelled runs.

use std::path::PathBuf;
use std::process::Command;

fn main() {
    let (sha, dirty) = git_identity().unwrap_or_else(|| ("unknown".to_string(), false));
    println!("cargo:rustc-env=TESTBED_GIT_SHA={sha}");
    println!("cargo:rustc-env=TESTBED_GIT_DIRTY={dirty}");
    watch_git_state();
}

/// The commit and whether tracked files differ from it.
fn git_identity() -> Option<(String, bool)> {
    let sha = git(&["rev-parse", "HEAD"])?;
    if sha.is_empty() {
        return None;
    }
    // Untracked files are deliberately excluded. A run writes its results under
    // the working directory, so counting untracked paths would mark every build
    // after the first run dirty while the compiled source had not moved. What
    // the flag is for is "does the tree differ from the commit in a way that
    // changed this binary", and that shows up as a modification to a tracked
    // file.
    let dirty = !git(&["status", "--porcelain", "--untracked-files=no"])?.is_empty();
    Some((sha, dirty))
}

/// Rebuild when the checked-out commit moves.
///
/// Without this the stamp is captured once and then survives every later
/// checkout, which is worse than having no stamp: it would confidently label a
/// run with the wrong commit. Guarded on existence, because naming a path that
/// does not exist makes cargo rerun the script on every single build.
fn watch_git_state() {
    let Some(dir) = git(&["rev-parse", "--absolute-git-dir"]) else {
        return;
    };
    let dir = PathBuf::from(dir);
    for name in ["HEAD", "index"] {
        let p = dir.join(name);
        if p.exists() {
            println!("cargo:rerun-if-changed={}", p.display());
        }
    }
}

fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git")
        .args(args)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8(out.stdout).ok()?.trim().to_string())
}
