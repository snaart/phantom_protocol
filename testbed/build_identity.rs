// How a build decides which commit it is.
//
// This file is textually included by `build.rs` and compiled a second time, as
// a module, by the crate's test build. Build scripts are not test targets, so
// logic that lives only in `build.rs` cannot be run by `cargo test` — and the
// precedence rule below is exactly the kind that is wrong in a way nobody
// notices, because a wrong answer here still produces a working binary carrying
// a plausible-looking identity.

/// Set by a deployment to state the commit it is building from.
///
/// The same name the compiled binary reads back, so a deployment sets the
/// variable the artifact will report.
const ENV_SHA: &str = "TESTBED_GIT_SHA";

/// Set alongside [`ENV_SHA`] when the deployed tree differed from that commit.
const ENV_DIRTY: &str = "TESTBED_GIT_DIRTY";

/// The build's git identity: the stated commit and whether the tree differed
/// from it.
///
/// The environment wins over git. The daemon builds from `/opt/phantom/src`,
/// which is a copy of the tree with no repository in it, so git has nothing to
/// say there and the only party that still knows which commit was copied is the
/// machine that did the copying. When it says so, that is the answer — and
/// there is no local git answer being overruled, because on such a host there
/// is none.
///
/// With nothing in the environment the build asks git, which is the ordinary
/// case for a checkout and is where the flag genuinely can be computed.
///
/// With neither, the identity is `unknown`. Building from a tarball or a
/// vendored copy is a normal thing to do, and an artifact that says it does not
/// know which code produced it is worth more than one carrying an invented
/// answer — the whole point of the stamp is that two runs can be shown to be
/// different builds.
fn resolve_identity(
    env_sha: Option<String>,
    env_dirty: Option<String>,
    from_git: impl FnOnce() -> Option<(String, bool)>,
) -> (String, bool) {
    if let Some(sha) = env_sha.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        return (sha.to_string(), parse_dirty(env_dirty.as_deref()));
    }
    // A blank value falls through deliberately. A deployment that fills the
    // variable with a command substitution gets an empty string, not an absent
    // variable, when the command fails — and stamping that would turn "we do
    // not know" into an identity field that is silently blank.
    from_git().unwrap_or_else(|| ("unknown".to_string(), false))
}

/// Reads the deployment's dirty flag.
///
/// Absent means clean: a deployment that names a commit and says nothing else
/// is deploying that commit. Anything else present and unrecognised is read as
/// dirty, which is the direction that costs less when it is wrong. A dirty
/// build mislabelled clean gets compared as though it were reproducible from
/// its SHA, and the conclusion drawn is about code nobody has; a clean build
/// mislabelled dirty only makes an analysis more cautious than it needed to be.
fn parse_dirty(value: Option<&str>) -> bool {
    match value.map(str::trim) {
        None | Some("") => false,
        Some(v) => !matches!(
            v.to_ascii_lowercase().as_str(),
            "0" | "false" | "no" | "clean"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Git stands in for a checkout that would answer if it were asked. Every
    /// test that expects the environment to win uses it, so "the environment
    /// won" means "git had an answer and it was not used" rather than "git had
    /// nothing to say either way".
    fn a_checkout() -> Option<(String, bool)> {
        Some(("f0f0f0f0".to_string(), true))
    }

    fn no_checkout() -> Option<(String, bool)> {
        None
    }

    #[test]
    fn the_environment_outranks_git() {
        let (sha, dirty) = resolve_identity(Some("abc123".into()), None, a_checkout);
        assert_eq!(sha, "abc123", "the deployment named the commit");
        assert!(!dirty, "no flag alongside the commit means a clean deploy");
    }

    #[test]
    fn the_environments_dirty_flag_is_carried_with_its_commit() {
        for flag in ["1", "true", "TRUE", "yes", " true "] {
            let (sha, dirty) =
                resolve_identity(Some("abc123".into()), Some(flag.into()), a_checkout);
            assert_eq!(sha, "abc123");
            assert!(dirty, "{flag:?} states a dirty tree");
        }
        for flag in ["0", "false", "No", "clean", "", "   "] {
            let (_, dirty) = resolve_identity(Some("abc123".into()), Some(flag.into()), a_checkout);
            assert!(!dirty, "{flag:?} states a clean tree");
        }
        // Not a word the flag knows. Read as dirty, so a garbled deployment
        // makes an analysis cautious rather than confident.
        let (_, dirty) = resolve_identity(Some("abc123".into()), Some("maybe".into()), a_checkout);
        assert!(dirty, "an unrecognised flag must not read as reproducible");
    }

    /// The flag alone describes nothing: without a commit from the same source
    /// there is no identity for it to qualify, so git's own answer stands whole.
    #[test]
    fn a_dirty_flag_without_a_commit_does_not_reach_gits_answer() {
        let (sha, dirty) = resolve_identity(None, Some("false".into()), a_checkout);
        assert_eq!(sha, "f0f0f0f0");
        assert!(
            dirty,
            "git said the checkout was dirty and nothing overrode it"
        );
    }

    #[test]
    fn git_answers_when_the_environment_is_silent() {
        let (sha, dirty) = resolve_identity(None, None, a_checkout);
        assert_eq!(sha, "f0f0f0f0");
        assert!(dirty);
    }

    /// The case the deployment recipe exists to fix, before it is fixed: a copy
    /// of the tree, no repository, nothing in the environment.
    #[test]
    fn with_neither_source_the_identity_is_unknown_rather_than_a_failure() {
        let (sha, dirty) = resolve_identity(None, None, no_checkout);
        assert_eq!(sha, "unknown");
        assert!(!dirty);
    }

    /// A variable filled by a command substitution that failed is present and
    /// empty. Stamping it would replace "unknown" with a blank field, which
    /// reads as data.
    #[test]
    fn a_blank_commit_falls_through_instead_of_being_stamped() {
        let (sha, _) = resolve_identity(Some("".into()), None, no_checkout);
        assert_eq!(sha, "unknown");
        let (sha, _) = resolve_identity(Some("   ".into()), None, a_checkout);
        assert_eq!(
            sha, "f0f0f0f0",
            "git still answers when the variable is blank"
        );
    }

    /// Whitespace around a real value is a shell artefact, not part of the SHA.
    #[test]
    fn a_commit_is_trimmed_before_it_is_stamped() {
        let (sha, _) = resolve_identity(Some("  abc123\n".into()), None, no_checkout);
        assert_eq!(sha, "abc123");
    }

    #[test]
    fn the_variable_names_are_the_ones_a_deployment_sets() {
        assert_eq!(ENV_SHA, "TESTBED_GIT_SHA");
        assert_eq!(ENV_DIRTY, "TESTBED_GIT_DIRTY");
    }
}
