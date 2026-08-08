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
//!
//! Asking git is not the only way to know, though, and on the host that matters
//! most it is the wrong one: the daemon is built on a VPS from `/opt/phantom/src`,
//! a copy of the tree carrying no repository, so git there has never had an
//! answer and the daemon's half of every run artifact read `unknown`. The
//! machine doing the copying does know, so the environment is consulted first
//! and git is the fallback — see `build_identity.rs`, which holds that
//! precedence rule where `cargo test` can reach it.

use std::path::PathBuf;
use std::process::Command;

include!("build_identity.rs");

fn main() {
    // Build-script output is cached, so without these the identity would
    // survive a change to the very variables that produced it — a redeploy
    // naming a new commit would restamp the old one.
    println!("cargo:rerun-if-env-changed={ENV_SHA}");
    println!("cargo:rerun-if-env-changed={ENV_DIRTY}");

    let (sha, dirty) = resolve_identity(
        std::env::var(ENV_SHA).ok(),
        std::env::var(ENV_DIRTY).ok(),
        git_identity,
    );
    println!("cargo:rustc-env={ENV_SHA}={sha}");
    println!("cargo:rustc-env={ENV_DIRTY}={dirty}");
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
