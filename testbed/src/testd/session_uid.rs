//! The `session_uid` allocator: a range no other run of the daemon can reissue.
//!
//! `sessions.jsonl`, `events.jsonl` and `windows.jsonl` are append-only and
//! outlive the process that wrote them, so one data directory holds many runs.
//! A uid is the only key joining a session's marks to its window series — and
//! `windows.jsonl` carries it inside the phase string `server:session:<uid>`,
//! so widening or re-typing it would move the break from the daemon into every
//! reader of the archive. The uid must therefore stay a plain ascending u64
//! whose values are never handed out twice, across restarts as well as within
//! one run.
//!
//! ## Why the clock is not enough
//!
//! Seeding the counter with microseconds since the epoch makes two runs
//! disjoint *only* while the clock moves forward by more than the number of
//! sessions the previous run accepted. Every part of that is an assumption
//! about a machine, not a property of the program:
//!
//! - a backwards NTP step lands the new run inside — or below — the previous
//!   run's range, and a range that starts below and ascends walks straight
//!   through it;
//! - a host with no battery-backed clock, a VM restored from a snapshot, or a
//!   container started from an image reads the *same* value on two boots, and
//!   the daemon binds and accepts before any time daemon has corrected it;
//! - [`crate::report::unix_nanos`] falls back to `0` when the clock is set
//!   before the epoch, which seeds the counter at zero and reproduces exactly
//!   the "starts at 1 every boot" behaviour the clock seed was introduced to
//!   remove — silently, because a zero seed still satisfies "the uid is between
//!   two readings of the clock".
//!
//! So the range is taken from the clock and then *recorded*. A boot starts
//! above the mark left by the last one, whatever the clock says, and the mark
//! is on disk before the first uid it covers is handed out.
//!
//! ## The lease
//!
//! Persisting every uid would put an `fsync` between `accept()` and the
//! handler, and latency added to the accept path is measured as protocol
//! behaviour — the one thing this harness must not manufacture. Instead a boot
//! reserves [`LEASE`] uids in a single durable write and hands them out from
//! memory; the mark is pushed forward again, off the accept path, once the
//! counter comes within [`LEASE`]/4 of the reservation.
//!
//! A crash therefore loses the unused tail of a lease and the next boot starts
//! above it. That is a gap, not a repeat: uids skip forward, and nothing that
//! reads these files assumes they are dense — `stall_verdict.py` and
//! `analyze.py` both key on the value, never on its successor.

use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::Arc;

/// The persisted high-water mark, in the data directory.
///
/// The data directory and not the signing-key directory: `--data-dir` and
/// `--signing-key-file` are independent flags that merely share a default, and
/// this file keys the journals, which live in the former.
const MARK_FILE: &str = "session-uid.hwm";

/// Staging name for the atomic replace. A partially written mark must never be
/// visible under the real name, because a truncated mark reads as garbage and
/// costs the boot its whole history.
const MARK_TMP_FILE: &str = "session-uid.hwm.tmp";

/// Uids reserved by one durable write.
///
/// Large enough that a run of this harness — a few hundred sessions in its
/// life — never touches the extension path at all, and small enough that the
/// forward skip a crash costs stays far below the microsecond-per-session
/// spacing the clock seed already implies.
pub const LEASE: u64 = 1 << 16;

/// How far ahead of the reservation the mark is pushed forward.
///
/// The extension is asynchronous, so this is headroom rather than a deadline:
/// 16384 uids must be issued before the counter could overrun a write that has
/// not landed, against a write that takes milliseconds.
const EXTEND_MARGIN: u64 = LEASE / 4;

/// Ceiling on the one-time journal scan performed when no mark exists.
///
/// The journals rotate at 256 MiB, so a scan can be asked to parse a quarter of
/// a gigabyte of JSON. A boot that takes a minute to start listening is a worse
/// failure than a boot that declares it could not recover the old range.
const BOOTSTRAP_SCAN_MAX_BYTES: u64 = 64 * 1024 * 1024;

/// How loud a [`UidNotice`] is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UidLevel {
    /// Where this boot's range came from. One per start, always emitted.
    Info,
    /// The range was recovered by a route that is not the mark itself.
    Warn,
    /// The mechanism is not working. Uniqueness across restarts is no longer
    /// guaranteed and the archive has to say so.
    Degraded,
}

/// Something the allocator has to say about where its range came from.
///
/// Returned rather than logged in place so the decision and its reporting can
/// be tested without a running collector, and so the caller emits every one of
/// them through the same path.
#[derive(Debug, Clone)]
pub struct UidNotice {
    pub level: UidLevel,
    /// The `kind` field of the archive record. Stable — an operator greps it.
    pub kind: &'static str,
    pub detail: String,
}

impl UidNotice {
    fn info(kind: &'static str, detail: String) -> Self {
        Self {
            level: UidLevel::Info,
            kind,
            detail,
        }
    }

    fn warn(kind: &'static str, detail: String) -> Self {
        Self {
            level: UidLevel::Warn,
            kind,
            detail,
        }
    }

    fn degraded(detail: String) -> Self {
        Self {
            level: UidLevel::Degraded,
            kind: "session_uid_degraded",
            detail,
        }
    }
}

/// State shared with the writer thread.
struct Shared {
    /// The next uid to hand out.
    next: AtomicU64,
    /// One past the highest uid the mark on disk covers.
    reserved: AtomicU64,
    /// Set while an extension is queued, so a burst of accepts produces one
    /// write rather than one per session.
    extending: AtomicBool,
}

/// The counter every accepted session draws its `session_uid` from.
pub struct SessionUidCounter {
    shared: Arc<Shared>,
    /// `None` once persistence is known to be impossible — the counter still
    /// hands out uids, it just cannot promise the next boot will clear them.
    extend: Option<Sender<u64>>,
}

impl SessionUidCounter {
    /// Open the allocator for a run whose clock reads `clock_us` microseconds
    /// since the epoch.
    ///
    /// The clock is a parameter and not a call to [`crate::report::unix_nanos`]
    /// so that a step backwards, a repeated reading and the epoch-fallback zero
    /// are all expressible; on a real boot the caller passes the real reading.
    ///
    /// Never fails. A measurement host that refuses to start because of a
    /// counter file is worse than one that starts and declares its own
    /// degradation, so every failure below returns a range plus a notice.
    pub fn open(clock_us: u64, dir: &Path) -> (Self, Vec<UidNotice>) {
        let paths = MarkPaths::in_dir(dir);
        let mut notices = Vec::new();
        let start = resolve_start(clock_us, dir, &paths, &mut notices);
        let reserved = start.saturating_add(LEASE);

        let shared = Arc::new(Shared {
            next: AtomicU64::new(start),
            reserved: AtomicU64::new(reserved),
            extending: AtomicBool::new(false),
        });

        // The reservation is made durable here, before `open` returns and so
        // before any uid it covers can be handed out. A uid is safe only once
        // the mark covering it is on disk; deferring this write until the
        // counter has issued something would reintroduce the whole defect as an
        // ordering, and a kill in the window would reissue the range.
        let extend = match paths.store(reserved) {
            Ok(()) => spawn_writer(shared.clone(), paths, &mut notices),
            Err(e) => {
                notices.push(UidNotice::degraded(format!(
                    "cannot write {}: {e} — this run's uids {start}..{reserved} are not \
                     recorded, and a restart may reissue them",
                    paths.mark.display()
                )));
                None
            }
        };

        (Self { shared, extend }, notices)
    }

    /// Take the next uid.
    ///
    /// One relaxed fetch-add plus one load on the accept path; the durable
    /// write it may schedule happens on the writer thread.
    pub fn next(&self) -> u64 {
        let uid = self.shared.next.fetch_add(1, Ordering::Relaxed);
        if uid.saturating_add(EXTEND_MARGIN) >= self.shared.reserved.load(Ordering::Acquire) {
            self.request_extend(uid);
        }
        uid
    }

    /// One past the highest uid the mark on disk currently covers.
    pub fn reserved(&self) -> u64 {
        self.shared.reserved.load(Ordering::Acquire)
    }

    fn request_extend(&self, uid: u64) {
        let Some(tx) = self.extend.as_ref() else {
            return;
        };
        if self
            .shared
            .extending
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        // A failed send means the writer has already given up and said so. The
        // election flag deliberately stays set: retrying would put a failed
        // send on the accept path once per session for the rest of the run.
        let _ = tx.send(uid.saturating_add(LEASE));
    }
}

/// Start the thread that owns the mark file after the initial reservation.
///
/// A thread rather than a task on the runtime because the work is a blocking
/// `fsync`, and rather than an inline write because the caller is the accept
/// loop.
fn spawn_writer(
    shared: Arc<Shared>,
    paths: MarkPaths,
    notices: &mut Vec<UidNotice>,
) -> Option<Sender<u64>> {
    let (tx, rx) = mpsc::channel::<u64>();
    let spawned = std::thread::Builder::new()
        .name("uid-mark".to_string())
        .spawn(move || {
            while let Ok(target) = rx.recv() {
                match paths.store(target) {
                    Ok(()) => {
                        // Publish only after the write: `reserved` is a claim
                        // about the disk, and a claim ahead of the disk is the
                        // reissue this module exists to prevent.
                        shared.reserved.store(target, Ordering::Release);
                        shared.extending.store(false, Ordering::Release);
                    }
                    Err(e) => {
                        // The log and not the archive, deliberately. Writing a
                        // record would mean holding a `CollectorHandle` for as
                        // long as this thread lives, and this thread lives as
                        // long as the counter does — past the point where
                        // shutdown drops its own handle and waits for the
                        // collector to drain. That wait would then always
                        // expire. A boot-time failure has no such problem and
                        // does reach the archive, through the notices returned
                        // by `open`.
                        tracing::error!(
                            path = %paths.mark.display(),
                            target,
                            reserved = shared.reserved.load(Ordering::Acquire),
                            error = %e,
                            "session uid mark not extended — uids past the reservation are not \
                             recorded, and a restart may reissue them"
                        );
                        // `extending` is left set and the thread returns: a
                        // wedged disk must not be retried once per session for
                        // the rest of the run. The degradation is declared once
                        // and the run continues issuing uids from memory.
                        return;
                    }
                }
            }
        });

    match spawned {
        Ok(_) => Some(tx),
        Err(e) => {
            notices.push(UidNotice::degraded(format!(
                "cannot start the session-uid mark writer: {e} — the reservation of {LEASE} uids \
                 stands, but it will not be extended"
            )));
            None
        }
    }
}

/// Decide where this boot's range begins.
fn resolve_start(
    clock_us: u64,
    dir: &Path,
    paths: &MarkPaths,
    notices: &mut Vec<UidNotice>,
) -> u64 {
    match read_mark(&paths.mark) {
        Ok(Some(persisted)) => {
            // The stored value is treated as already consumed. It is the top of
            // a reservation, and whether the last run actually reached it is
            // unknowable — assuming it did costs a gap, assuming it did not
            // costs a repeat.
            let start = clock_us.max(persisted.saturating_add(1));
            notices.push(UidNotice::info(
                "session_uid_resumed",
                format!(
                    "first uid {start} (clock {clock_us}, mark {persisted} in {})",
                    paths.mark.display()
                ),
            ));
            start
        }
        Ok(None) => match scan_journals_for_max_uid(dir, notices) {
            Some(max) => {
                let start = clock_us.max(max.saturating_add(1));
                notices.push(UidNotice::warn(
                    "session_uid_bootstrap",
                    format!(
                        "no {} yet; recovered from the journals in {}, highest uid {max}, \
                         first uid {start}",
                        MARK_FILE,
                        dir.display()
                    ),
                ));
                start
            }
            None => {
                notices.push(UidNotice::info(
                    "session_uid_fresh",
                    format!("no {MARK_FILE} and no prior sessions; first uid {clock_us}"),
                ));
                clock_us
            }
        },
        Err(e) => {
            // Not fatal, and deliberately not recovered from the journals
            // either: a mark that exists and cannot be read describes a host
            // whose data directory is not trustworthy, so the honest move is
            // the clock plus a loud record of what was lost.
            notices.push(UidNotice::degraded(format!(
                "cannot read {}: {e} — falling back to the clock, so uids from {clock_us} may \
                 collide with an earlier run's",
                paths.mark.display()
            )));
            clock_us
        }
    }
}

/// Read the mark. `Ok(None)` means "no mark yet", which is not an error.
fn read_mark(path: &Path) -> std::io::Result<Option<u64>> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let trimmed = text.trim();
    trimmed.parse::<u64>().map(Some).map_err(|e| {
        // Quote a bounded prefix: the file is attacker-free but it may be
        // megabytes of something else entirely, and this string reaches a log.
        let shown: String = trimmed.chars().take(32).collect();
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{shown:?} is not a uid mark: {e}"),
        )
    })
}

/// One-time recovery for a host that has journals but no mark.
///
/// Only reached on the boot that introduces the mark file. Every later boot
/// reads the mark and never touches the journals.
fn scan_journals_for_max_uid(dir: &Path, notices: &mut Vec<UidNotice>) -> Option<u64> {
    let mut max: Option<u64> = None;
    for name in ["sessions.jsonl", "sessions.jsonl.1"] {
        let path = dir.join(name);
        let len = match std::fs::metadata(&path) {
            Ok(m) => m.len(),
            Err(_) => continue,
        };
        if len == 0 {
            continue;
        }
        if len > BOOTSTRAP_SCAN_MAX_BYTES {
            notices.push(UidNotice::warn(
                "session_uid_bootstrap",
                format!(
                    "{} is {len} bytes, past the {BOOTSTRAP_SCAN_MAX_BYTES}-byte scan bound; \
                     not searched for a previous uid range",
                    path.display()
                ),
            ));
            continue;
        }
        let file = match File::open(&path) {
            Ok(f) => f,
            Err(e) => {
                notices.push(UidNotice::degraded(format!(
                    "cannot scan {} for a previous uid range: {e}",
                    path.display()
                )));
                continue;
            }
        };
        for line in BufReader::new(file).lines() {
            // A read error mid-file (including invalid UTF-8) ends this
            // generation rather than the recovery: whatever was parsed so far
            // still raises the floor, which is the only thing being asked for.
            let Ok(line) = line else { break };
            let Ok(value) = serde_json::from_str::<serde_json::Value>(&line) else {
                continue;
            };
            if let Some(uid) = value.get("session_uid").and_then(serde_json::Value::as_u64) {
                max = Some(max.map_or(uid, |m| m.max(uid)));
            }
        }
    }
    max
}

/// The mark and its staging name, resolved once.
struct MarkPaths {
    mark: PathBuf,
    tmp: PathBuf,
}

impl MarkPaths {
    fn in_dir(dir: &Path) -> Self {
        Self {
            mark: dir.join(MARK_FILE),
            tmp: dir.join(MARK_TMP_FILE),
        }
    }

    /// Replace the mark with `value`, durably.
    ///
    /// Write-then-rename rather than write-in-place: a mark truncated by a
    /// crash halfway through `write(2)` parses as garbage, and a garbage mark
    /// is indistinguishable from no mark at all — which loses the range the
    /// file exists to carry. The rename is atomic, so the name always refers to
    /// a whole number.
    fn store(&self, value: u64) -> std::io::Result<()> {
        {
            let mut f = create_mark_file(&self.tmp)?;
            f.write_all(format!("{value}\n").as_bytes())?;
            f.sync_all()?;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // Explicitly, rather than trusting the creation mode: on a second
            // write the staging file already exists and `.mode()` applies only
            // at creation. It is not a secret, and an operator diagnosing a uid
            // range must be able to read it without becoming its owner.
            std::fs::set_permissions(&self.tmp, std::fs::Permissions::from_mode(0o644))?;
        }
        std::fs::rename(&self.tmp, &self.mark)?;
        #[cfg(unix)]
        {
            // The rename is a directory operation, so the file's own fsync says
            // nothing about it: the bytes can be on disk under no name at all.
            // Best-effort, because a filesystem that refuses to sync a
            // directory handle must not turn a mark that was written into a
            // degradation that was not.
            if let Some(dir) = self.mark.parent() {
                if let Ok(d) = File::open(dir) {
                    let _ = d.sync_all();
                }
            }
        }
        Ok(())
    }
}

#[cfg(unix)]
fn create_mark_file(path: &Path) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o644)
        .open(path)
}

#[cfg(not(unix))]
fn create_mark_file(path: &Path) -> std::io::Result<File> {
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "tb-uid-{}-{}-{:?}",
            tag,
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).expect("mkdir");
        d
    }

    /// Take `n` uids from a counter opened at `clock_us`, then close it — the
    /// shape of one daemon run against a data directory.
    fn run(clock_us: u64, dir: &Path, n: usize) -> (Vec<u64>, Vec<UidNotice>) {
        let (c, notices) = SessionUidCounter::open(clock_us, dir);
        let uids = (0..n).map(|_| c.next()).collect();
        (uids, notices)
    }

    fn assert_disjoint_and_ascending(a: &[u64], b: &[u64]) {
        let mut all: Vec<u64> = a.iter().chain(b.iter()).copied().collect();
        let total = all.len();
        all.sort_unstable();
        all.dedup();
        assert_eq!(
            all.len(),
            total,
            "the second run reissued a uid from the first: {:?} then {:?}",
            &a[..4.min(a.len())],
            &b[..4.min(b.len())]
        );
        assert!(
            b[0] > a[a.len() - 1],
            "uids must keep ascending across a restart, got {} then {}",
            a[a.len() - 1],
            b[0]
        );
    }

    /// A backwards clock step is the case the clock seed cannot survive: the
    /// new run's seed lands inside the old run's range and ascends through it.
    #[test]
    fn a_backwards_clock_step_does_not_reissue_a_uid() {
        let dir = tmpdir("back");
        let (a, _) = run(1_800_000_000_000_000, &dir, 64);
        // A full second backwards — an NTP correction, not a leap.
        let (b, _) = run(1_799_999_000_000_000, &dir, 64);
        assert_disjoint_and_ascending(&a, &b);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A host with no battery-backed clock, a restored snapshot, or a container
    /// from an image reads the same value on two boots — and the daemon binds
    /// and accepts before any time daemon corrects it.
    #[test]
    fn an_unmoved_clock_does_not_reissue_a_uid() {
        let dir = tmpdir("frozen");
        let (a, _) = run(1_800_000_000_000_000, &dir, 64);
        let (b, _) = run(1_800_000_000_000_000, &dir, 64);
        assert_disjoint_and_ascending(&a, &b);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `report::unix_nanos()` returns 0 when the clock is set before the epoch,
    /// which seeds the counter at zero. The second boot must not start at 1.
    #[test]
    fn a_zero_clock_reading_does_not_restart_the_sequence() {
        let dir = tmpdir("zero");
        let (a, _) = run(0, &dir, 64);
        assert_eq!(
            a[0], 0,
            "a zero reading is taken at face value on a fresh dir"
        );
        let (b, _) = run(0, &dir, 64);
        assert_disjoint_and_ascending(&a, &b);
        assert!(
            b[0] >= LEASE,
            "the second run must start above the first run's reservation, got {}",
            b[0]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A run that dies mid-lease never extends the mark. The next boot must
    /// start above what was reserved — gaps are fine, repeats are not.
    #[test]
    fn a_crash_mid_lease_skips_forward_rather_than_repeating() {
        let dir = tmpdir("crash");
        let (a, _) = run(1_800_000_000_000_000, &dir, 3);
        let mark = read_mark(&dir.join(MARK_FILE))
            .expect("readable")
            .expect("written");
        assert_eq!(mark, a[0] + LEASE, "the boot reserves a whole lease");

        let (b, _) = run(1_800_000_000_000_000, &dir, 3);
        assert!(
            b[0] > mark,
            "the next boot must start past the persisted mark {mark}, got {}",
            b[0]
        );
        assert_disjoint_and_ascending(&a, &b);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The mark is written before the first uid it covers is handed out. A
    /// process killed between the two would otherwise reissue everything.
    #[test]
    fn the_mark_is_on_disk_before_the_first_uid_is_issued() {
        let dir = tmpdir("order");
        let (c, _) = SessionUidCounter::open(1_800_000_000_000_000, &dir);
        let mark = read_mark(&dir.join(MARK_FILE))
            .expect("readable")
            .expect("written");
        assert_eq!(
            mark,
            1_800_000_000_000_000 + LEASE,
            "the reservation covering the first uid must already be durable"
        );
        assert_eq!(c.next(), 1_800_000_000_000_000);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn the_mark_is_readable_without_being_the_owner() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmpdir("mode");
        let _ = SessionUidCounter::open(1_800_000_000_000_000, &dir);
        let mode = std::fs::metadata(dir.join(MARK_FILE))
            .expect("stat")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode, 0o644,
            "the mark is not a secret and must stay diagnosable"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Garbage under the mark's name must not stop the daemon, and must not
    /// pass silently either: what it costs is the previous range.
    #[test]
    fn an_unparsable_mark_is_declared_and_the_daemon_still_starts() {
        let dir = tmpdir("garbage");
        std::fs::write(dir.join(MARK_FILE), b"\x00\x01not a number\n").expect("write");
        let (c, notices) = SessionUidCounter::open(1_800_000_000_000_000, &dir);
        assert_eq!(c.next(), 1_800_000_000_000_000, "a counter is still minted");
        let degraded: Vec<&UidNotice> = notices
            .iter()
            .filter(|n| n.level == UidLevel::Degraded)
            .collect();
        assert_eq!(
            degraded.len(),
            1,
            "exactly one degradation, got {notices:?}"
        );
        assert!(
            degraded[0].detail.contains(MARK_FILE),
            "the record must name the file: {}",
            degraded[0].detail
        );
        // And the replacement is written, so the *next* boot is sound again.
        let mark = read_mark(&dir.join(MARK_FILE))
            .expect("readable")
            .expect("rewritten");
        assert_eq!(mark, 1_800_000_000_000_000 + LEASE);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An empty mark file is a crash during a non-atomic write. It is the same
    /// failure as garbage and must be reported, not read as "no mark".
    #[test]
    fn a_truncated_mark_is_not_mistaken_for_a_missing_one() {
        let dir = tmpdir("trunc");
        std::fs::write(dir.join(MARK_FILE), b"").expect("write");
        let (_, notices) = SessionUidCounter::open(1_800_000_000_000_000, &dir);
        assert!(
            notices.iter().any(|n| n.level == UidLevel::Degraded),
            "an empty mark must be declared, got {notices:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn an_unreadable_mark_is_declared_and_the_daemon_still_starts() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmpdir("eacces");
        let path = dir.join(MARK_FILE);
        std::fs::write(&path, b"12345\n").expect("write");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).expect("chmod");
        if std::fs::read_to_string(&path).is_ok() {
            // Running as root, where mode 000 grants read anyway. The case this
            // test describes cannot be produced here; the garbage-mark test
            // covers the same branch by content instead of by permission.
            let _ = std::fs::remove_dir_all(&dir);
            return;
        }
        let (c, notices) = SessionUidCounter::open(1_800_000_000_000_000, &dir);
        assert_eq!(c.next(), 1_800_000_000_000_000, "a counter is still minted");
        assert!(
            notices.iter().any(|n| n.level == UidLevel::Degraded),
            "an unreadable mark must be declared, got {notices:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A data directory that cannot be written must still yield a counter — the
    /// daemon's job is to measure, and refusing to boot over a bookkeeping file
    /// costs the whole run.
    #[test]
    fn an_unwritable_mark_is_declared_and_the_daemon_still_starts() {
        let dir = tmpdir("nowrite");
        // A directory under the staging name makes every write fail for any
        // user, root included — unlike a mode bit, which root ignores.
        std::fs::create_dir_all(dir.join(MARK_TMP_FILE)).expect("mkdir");
        let (c, notices) = SessionUidCounter::open(1_800_000_000_000_000, &dir);
        assert_eq!(c.next(), 1_800_000_000_000_000, "a counter is still minted");
        assert!(
            notices.iter().any(|n| n.level == UidLevel::Degraded),
            "an unwritable mark must be declared, got {notices:?}"
        );
        assert!(
            !dir.join(MARK_FILE).exists(),
            "nothing was left under the real name"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A host that has been recording sessions since before the mark existed
    /// must not restart inside the range those sessions already used.
    #[test]
    fn a_host_with_journals_but_no_mark_starts_above_them() {
        let dir = tmpdir("bootstrap");
        std::fs::write(
            dir.join("sessions.jsonl"),
            "{\"session_uid\":41,\"listener\":\"udp\"}\n\
             not json at all\n\
             {\"session_uid\":9000,\"listener\":\"tcp\"}\n",
        )
        .expect("write");
        std::fs::write(
            dir.join("sessions.jsonl.1"),
            "{\"session_uid\":9001,\"listener\":\"tcp\"}\n",
        )
        .expect("write");

        // A clock far below the recorded uids, so only the scan can save it.
        let (c, notices) = SessionUidCounter::open(7, &dir);
        assert_eq!(
            c.next(),
            9002,
            "start above the highest uid in either generation"
        );
        assert!(
            notices
                .iter()
                .any(|n| n.level == UidLevel::Warn && n.detail.contains("9001")),
            "the recovery must say what it found, got {notices:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The clock still wins when it is ahead: the scan raises the floor, it
    /// does not replace the seed.
    #[test]
    fn the_bootstrap_scan_never_lowers_the_start() {
        let dir = tmpdir("bootstrap-hi");
        std::fs::write(dir.join("sessions.jsonl"), "{\"session_uid\":41}\n").expect("write");
        let (c, _) = SessionUidCounter::open(1_800_000_000_000_000, &dir);
        assert_eq!(c.next(), 1_800_000_000_000_000);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The journals rotate at 256 MiB. A boot must not turn into a minute of
    /// JSON parsing, so an oversized generation is skipped and said so.
    #[test]
    fn an_oversized_journal_is_skipped_rather_than_parsed() {
        let dir = tmpdir("huge");
        let path = dir.join("sessions.jsonl");
        {
            let mut f = File::create(&path).expect("create");
            f.write_all(b"{\"session_uid\":9000}\n").expect("write");
            // Sparse: the length is what the bound is checked against, and
            // producing it for real would cost the test 64 MiB of I/O.
            f.set_len(BOOTSTRAP_SCAN_MAX_BYTES + 1).expect("set_len");
        }
        let (c, notices) = SessionUidCounter::open(7, &dir);
        assert_eq!(c.next(), 7, "the uid on line 1 must not have been read");
        assert!(
            notices
                .iter()
                .any(|n| n.level == UidLevel::Warn && n.detail.contains("scan bound")),
            "the skip must be declared, got {notices:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Crossing the lease threshold pushes the mark forward, so a long run does
    /// not hand out uids past what disk covers.
    #[test]
    fn the_lease_is_extended_before_it_runs_out() {
        let dir = tmpdir("lease");
        let (c, _) = SessionUidCounter::open(1_800_000_000_000_000, &dir);
        let initial = c.reserved();

        // Up to the trigger at `reserved - LEASE/4` and one past it.
        for _ in 0..(LEASE - EXTEND_MARGIN + 1) {
            c.next();
        }

        // The write is on another thread; wait for it rather than assume it,
        // with a bound so a wedged writer fails the test instead of hanging it.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while c.reserved() == initial && std::time::Instant::now() < deadline {
            std::thread::yield_now();
        }
        assert!(
            c.reserved() > initial,
            "the reservation must move before the counter reaches it: still {initial}"
        );
        let mark = read_mark(&dir.join(MARK_FILE))
            .expect("readable")
            .expect("written");
        assert_eq!(
            mark,
            c.reserved(),
            "the published reservation is the one on disk"
        );
        assert!(
            c.next() < mark,
            "the counter must still be inside the reservation it published"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Whatever the lease did, the next boot starts above the mark. This is the
    /// only invariant the archive actually depends on.
    #[test]
    fn a_restart_after_an_extension_still_does_not_repeat() {
        let dir = tmpdir("lease-restart");
        let (c, _) = SessionUidCounter::open(1_800_000_000_000_000, &dir);
        let mut a = Vec::new();
        for _ in 0..(LEASE - EXTEND_MARGIN + 1) {
            a.push(c.next());
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while c.reserved() == 1_800_000_000_000_000 + LEASE && std::time::Instant::now() < deadline
        {
            std::thread::yield_now();
        }
        drop(c);

        let (b, _) = run(1_800_000_000_000_000, &dir, 4);
        assert_disjoint_and_ascending(&a, &b);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
