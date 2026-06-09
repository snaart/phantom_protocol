# Incident Response Playbook

Reference document for the maintainers when a security report arrives.
Complements `SECURITY.md` (which is the external-facing disclosure
policy) by detailing the internal-facing steps.

---

## 0. At-a-glance triage

```
                    ┌────────────────────────────────────┐
                    │   private report received           │
                    └─────────────┬──────────────────────┘
                                  │
            ┌─────────────────────┴─────────────────────┐
            │ within 5 business days                    │
            │  • Acknowledge receipt                    │
            │  • Assign CVE-track number internally     │
            │  • Confirm in-scope (see SECURITY.md §1)  │
            └─────────────────────┬─────────────────────┘
                                  │
            ┌─────────────────────┴─────────────────────┐
            │ within 14 business days                   │
            │  • Triage severity (CVSS 4.0)             │
            │  • Reproduce in lab                       │
            │  • Decide: accept / clarify / reject      │
            └─────────────────────┬─────────────────────┘
                                  │
            ┌─────────────────────┴─────────────────────┐
            │ severity-driven fix window                │
            │  Critical / High:  7 days                 │
            │  Medium:          30 days                 │
            │  Low:             90 days                 │
            └─────────────────────┬─────────────────────┘
                                  │
            ┌─────────────────────┴─────────────────────┐
            │ Coordinated release                        │
            │  • Pre-disclose to direct downstreams      │
            │  • Cut release with the fix                │
            │  • Publish CVE + advisory                  │
            │  • Notify reporter of public timeline      │
            └────────────────────────────────────────────┘
```

Standard public-disclosure SLA: **90 days** from receipt. Extensions
granted for downstream coordination on request.

---

## 1. Severity classification

We use **CVSS 4.0** with phantom-specific defaults to remove the usual
ambiguity:

| Field | Default | Notes |
| --- | --- | --- |
| Attack Vector | Network | the entire library exists to face hostile networks |
| Attack Complexity | Low | unless the issue requires multiple race-conditions, leaked secrets, or specific cipher choices |
| Privileges Required | None |
| User Interaction | None |
| Scope | Unchanged | the SDK is library code; "system" boundary is the host process |
| Confidentiality | varies | High for plaintext leaks; Low for length-only side channels |
| Integrity | varies | High if ciphertext can be silently mutated; otherwise None |
| Availability | varies | High for unauth panic-on-input DoS; Low for transient hangs |

Severity buckets used in the timeline above:

| CVSS | Severity bucket | Fix window |
| --- | --- | --- |
| 9.0-10.0 | Critical | 7 days |
| 7.0-8.9 | High | 7 days |
| 4.0-6.9 | Medium | 30 days |
| 0.1-3.9 | Low | 90 days |

A finding that breaks one of the three documented invariants
(`SECURITY.md` §3) is always **at least** High regardless of CVSS arithmetic.

---

## 2. Roles

| Role | Responsibility |
| --- | --- |
| Triage Lead | Acknowledges report, runs initial reproduction, assigns severity. |
| Fix Author | Writes the patch + tests; usually the same person as Triage Lead unless deep expertise is needed. |
| Reviewer | Independent code review by another maintainer. Required for any fix that touches `core/src/crypto/` or `core/src/transport/handshake.rs`. |
| Release Captain | Cuts the release, drafts CHANGELOG entry, files the GHSA / CVE. |

For solo-maintainer operation, all four roles collapse into one person —
in that case the Reviewer responsibility is satisfied by mandatory
24-hour cool-off between writing the fix and merging it.

---

## 3. Reproduction discipline

Before declaring "accepted", the report must be reproduced:

- In a clean checkout of `main` at the latest commit.
- With `cargo test --workspace` green on that commit (so the issue is
  isolated from unrelated test flakes).
- With the reporter's exact reproducer if one was provided. If they
  provided a fuzz seed, replay it through `cargo fuzz run <target>
  <seed-path>`.
- Captured as a new test in `core/tests/security_invariants.rs` (or
  in a fuzz corpus) BEFORE the fix lands. The test must fail on
  pre-fix `main`, pass after the fix. This guarantees regression
  coverage forever.

If the issue cannot be reproduced after 14 days, return to the reporter
with a request for more detail and pause the timeline.

---

## 4. Fix authoring

- The fix touches the **smallest surface possible**. Refactoring is
  forbidden in a security commit — it dilutes diff review and risks
  introducing new bugs in the embargoed window.
- Every fix carries:
  - A new test (see §3).
  - A CHANGELOG entry under `Security:`.
  - A doc comment update if the fix changes a documented invariant.
  - A `# SAFETY` or `# PANIC-SAFETY` comment update if the fix removes
    one of those sites.
- The fix is branched off `main` into a private branch (no public PR
  yet). Reviewer reviews via direct git access or signed email patches.

---

## 5. Coordinated disclosure

For findings that are likely to affect downstream consumers:

1. **Embargoed pre-notice (T-7 days)** to a list of trusted downstreams
   who have asked to be on the embargo list. Includes:
   - Severity rating.
   - Affected versions.
   - Whether a patch is ready (don't share the patch until T-1).
   - Mitigations applicable in the embargo window (config changes,
     traffic blocking, etc.).
2. **Pre-release patch (T-1 day)** to the same list, plus the reporter.
3. **Public release (T-0)** — push tag, publish crate, file GHSA / CVE.

The embargo list lives outside this repository (separate access list).
Maintainers add downstreams on request after a quick check (apparent
real production usage, no anonymous accounts).

---

## 6. CVE / GHSA filing

Phantom Protocol uses **GitHub Security Advisories** (GHSA) as the primary
identifier and requests CVE assignment through GitHub's CNA.

GHSA fields:

- **Title**: `Phantom Protocol <vN.N.N>: <one-line description>`
- **Affected versions**: pinned by `Cargo.toml`'s `[package].version`
  range syntax.
- **CWE**: pick the closest from the OWASP / MITRE catalog.
- **Patches**: link to the merge commit on `main` and the tagged
  release.
- **Workarounds**: text from the embargoed pre-notice if applicable.
- **Credits**: the reporter, unless they requested anonymity.

---

## 7. Post-incident

Within two weeks of a Critical / High disclosure:

- Write a **post-mortem** under `docs/security/postmortems/YYYY-MM-DD-<short-slug>.md`.
  Audience: public. Format: "What happened / How we found it / Why our
  existing tests didn't catch it / What we changed beyond the patch /
  Timeline".
- File a process improvement item if the existing playbook missed a
  step. The playbook is a living document.

For Medium / Low, an internal lessons-learned note is fine; no public
post-mortem required.

---

## 8. Contacts

(Maintainer roster — update when the project changes hands.)

- Primary contact: `security@phantom-protocol.invalid` (PGP-signed mail
  preferred; key fingerprint in `SECURITY.md`).
- Backup contact: ditto.
- Out-of-band escalation: see organisation directory.

PGP key rotation: at least every 24 months. The previous key remains
valid for verification for 12 months after rotation.

---

## 9. Tools and references

- GHSA filing: https://github.com/<org>/phantom-protocol/security/advisories/new
- CVE search: https://nvd.nist.gov/vuln/search
- CVSS 4.0 calculator: https://www.first.org/cvss/calculator/4-0
- Fuzz harness: `fuzz/` (Phase 6.4) — reproduce known crashing inputs.
- Negative test suite: `core/tests/security_invariants.rs` (Phase 6.8).
- Threat model: `docs/security/threat-model.md` (Phase 6.1).
- Protocol spec: `docs/protocol/PROTOCOL.md` (Phase 6.2).
