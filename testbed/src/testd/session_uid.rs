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
//!
//! The extension is asked for from `next()`, which is the only place that knows
//! a uid has been handed out — and therefore the one place that stops asking
//! when a burst ends. So the same writer thread also tops the mark up on a
//! timer and once more when the counter is released, and what it records then
//! is what was issued rather than what was last reserved. Without that, a run
//! ends with uids above the mark, and they are the ones a restart reissues.
//!
//! ## Saying so
//!
//! Every route to a range — the mark, the journals, the clock alone — reports
//! where it came from, and every failure reports what it cost. A failure at
//! boot travels out through the notices [`SessionUidCounter::open`] returns; a
//! failure later in the run has no return value to travel on and goes through
//! the [`NoticeSink`] instead, so that both end up in `events.jsonl` under the
//! `session_uid_degraded` kind an operator greps for. A run whose uids are not
//! guaranteed must say so in the same files those uids key.

use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::sync::Arc;
use std::time::Duration;

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

/// How often the mark writer checks whether the counter has run past the mark.
///
/// The extension is triggered from `next()`, so the end of a burst leaves the
/// counter above what disk covers with nothing left to trigger a write — the
/// uids in that gap were issued and are not recorded. The check costs nothing
/// while the mark is ahead, which is every tick of an idle daemon.
const TOPUP_INTERVAL: Duration = Duration::from_secs(2);

/// The journals a `session_uid` can appear in, both retained generations.
///
/// `events.jsonl` leads because it is where a uid is written *first*: it is
/// minted at accept and recorded there immediately, while the `sessions.jsonl`
/// record is written at close. Every session that was alive when a daemon died
/// therefore appears in the events journal and nowhere else, so scanning only
/// the session journal recovers a floor below uids that already key marks and a
/// window series.
const JOURNALS: [&str; 4] = [
    "events.jsonl",
    "events.jsonl.1",
    "sessions.jsonl",
    "sessions.jsonl.1",
];

/// How many unreadable lines one journal generation may yield before the scan
/// stops reading it.
///
/// A single bad line is skipped, because a journal is append-only and the uids
/// that matter most are the newest — they sit after whatever byte went wrong.
/// A device that returns an error for every read would otherwise spin here.
const MAX_UNREADABLE_LINES: usize = 1024;

/// Ceiling on the one-time journal scan performed when no mark exists.
///
/// The journals rotate at 256 MiB, so a scan can be asked to parse a quarter of
/// a gigabyte of JSON. A boot that takes a minute to start listening is a worse
/// failure than a boot that declares it could not recover the old range.
const BOOTSTRAP_SCAN_MAX_BYTES: u64 = 64 * 1024 * 1024;

/// The largest uid this archive can carry without losing it.
///
/// A uid rides inside JSON numbers that every reader of these files parses as
/// doubles — `stall_verdict.py`, `analyze.py`, `jq` — and those are exact only
/// below 2^53. It also rides inside the `server:session:<uid>` phase string,
/// where a value that does not round-trip stops joining anything.
const MAX_EXACT_UID: u64 = 1 << 53;

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

/// Where a notice raised *after* [`SessionUidCounter::open`] has returned goes.
///
/// The mark is extended off the accept path, on a thread that lives as long as
/// the counter does, so a failure there has no return value to travel out on.
/// It is still the same failure as a boot-time one — uids are being handed out
/// that no restart will know about — and it has to reach the same place.
///
/// The sink owns both halves of the reporting, the log and the archive, exactly
/// as the caller does for the notices `open` returns; when there is no sink the
/// allocator logs the notice itself rather than dropping it.
pub type NoticeSink = Arc<dyn Fn(UidNotice) + Send + Sync>;

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
    /// Set once the run has declared that the mark is no longer tracking the
    /// uids being issued. A wedged data directory fails every write after the
    /// first, and repeating the same record for each of them would bury the
    /// journal in one machine's disk fault.
    declared: AtomicBool,
}

/// The counter every accepted session draws its `session_uid` from.
pub struct SessionUidCounter {
    shared: Arc<Shared>,
    /// Shared with the writer thread, and kept here for the final top-up: the
    /// last thing a run does is record what it actually handed out.
    paths: Arc<MarkPaths>,
    /// `None` once persistence is known to be impossible — the counter still
    /// hands out uids, it just cannot promise the next boot will clear them.
    extend: Option<Sender<u64>>,
    /// Joined on drop, so the writer's final top-up is ordered before the run
    /// that owns this counter reports itself finished.
    writer: Option<std::thread::JoinHandle<()>>,
    sink: Option<NoticeSink>,
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
        Self::open_with_sink(clock_us, dir, None)
    }

    /// [`SessionUidCounter::open`], plus somewhere for the notices raised after
    /// it returns to go. See [`NoticeSink`].
    pub fn open_with_sink(
        clock_us: u64,
        dir: &Path,
        sink: Option<NoticeSink>,
    ) -> (Self, Vec<UidNotice>) {
        let paths = Arc::new(MarkPaths::in_dir(dir));
        let mut notices = Vec::new();
        let start = resolve_start(clock_us, dir, &paths, &mut notices);
        let reserved = start.saturating_add(LEASE);

        let shared = Arc::new(Shared {
            next: AtomicU64::new(start),
            reserved: AtomicU64::new(reserved),
            extending: AtomicBool::new(false),
            declared: AtomicBool::new(false),
        });

        // The reservation is made durable here, before `open` returns and so
        // before any uid it covers can be handed out. A uid is safe only once
        // the mark covering it is on disk; deferring this write until the
        // counter has issued something would reintroduce the whole defect as an
        // ordering, and a kill in the window would reissue the range.
        let (extend, writer) = match paths.store(reserved) {
            Ok(()) => {
                match spawn_writer(shared.clone(), paths.clone(), sink.clone(), &mut notices) {
                    Some((tx, handle)) => (Some(tx), Some(handle)),
                    None => (None, None),
                }
            }
            Err(e) => {
                notices.push(UidNotice::degraded(format!(
                    "cannot write {}: {e} — this run's uids {start}..{reserved} are not \
                     recorded, and a restart may reissue them",
                    paths.mark.display()
                )));
                // This notice is the run's one declaration; the same directory
                // will refuse the top-up on the way out, and that is the same
                // failure rather than a second one.
                shared.declared.store(true, Ordering::Release);
                (None, None)
            }
        };

        (
            Self {
                shared,
                paths,
                extend,
                writer,
                sink,
            },
            notices,
        )
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

impl Drop for SessionUidCounter {
    /// Record what this run actually handed out.
    ///
    /// Dropping the sender ends the writer's loop, and joining it is what
    /// orders its last top-up before this returns; the inline attempt after
    /// covers a run that never had a writer at all. Neither is on the accept
    /// path — the counter is released at shutdown, and an `fsync` between
    /// `accept()` and the handler is measured as protocol behaviour, which is
    /// the one thing this harness must not manufacture.
    fn drop(&mut self) {
        self.extend.take();
        if let Some(h) = self.writer.take() {
            let _ = h.join();
        }
        if let Err(e) = top_up(&self.shared, &self.paths) {
            declare_write_failure(&self.paths, &self.shared, &e, self.sink.as_ref());
        }
    }
}

/// Push the mark up to what has actually been issued, if it has fallen behind.
///
/// `reserved` moves only after the write lands, so it stays a claim about the
/// disk rather than an intention — a claim ahead of the disk is the reissue
/// this module exists to prevent.
fn top_up(shared: &Shared, paths: &MarkPaths) -> std::io::Result<()> {
    let issued_next = shared.next.load(Ordering::Acquire);
    if issued_next <= shared.reserved.load(Ordering::Acquire) {
        return Ok(());
    }
    paths.store(issued_next)?;
    shared.reserved.fetch_max(issued_next, Ordering::AcqRel);
    Ok(())
}

/// Install a reservation the writer thread was asked for.
///
/// Never below what the mark already covers: a request is composed on the
/// accept path and can be overtaken by a top-up before it is served, and
/// rewriting the smaller number would retract a range that is already recorded
/// — which is a reissue, the one outcome this module has to prevent.
fn store_target(shared: &Shared, paths: &MarkPaths, target: u64) -> std::io::Result<()> {
    let target = target.max(shared.reserved.load(Ordering::Acquire));
    paths.store(target)?;
    shared.reserved.fetch_max(target, Ordering::AcqRel);
    shared.extending.store(false, Ordering::Release);
    Ok(())
}

/// Say, once, that the mark has stopped tracking the uids being issued.
///
/// Through the sink when there is one, because this is the same failure as a
/// boot-time write failure and belongs in the same journal — an operator
/// grepping `events.jsonl` for `session_uid_degraded`, which is what the
/// harness's README tells them to do, must not see a clean run. Without a sink
/// the log is all there is, and a silent return would be worse.
fn declare_write_failure(
    paths: &MarkPaths,
    shared: &Shared,
    e: &std::io::Error,
    sink: Option<&NoticeSink>,
) {
    if shared.declared.swap(true, Ordering::AcqRel) {
        return;
    }
    let reserved = shared.reserved.load(Ordering::Acquire);
    let notice = UidNotice::degraded(format!(
        "cannot write {}: {e} — uids past {reserved} are not recorded, and a restart may \
         reissue them",
        paths.mark.display()
    ));
    match sink {
        Some(s) => s(notice),
        None => tracing::error!(detail = %notice.detail, "session uid range degraded"),
    }
}

/// Start the thread that owns the mark file after the initial reservation.
///
/// A thread rather than a task on the runtime because the work is a blocking
/// `fsync`, and rather than an inline write because the caller is the accept
/// loop.
///
/// It waits with a timeout rather than blocking on the channel so the same
/// thread also carries the top-up: an extension is requested from `next()`, and
/// a run whose accepts have stopped has nothing left to ask with.
fn spawn_writer(
    shared: Arc<Shared>,
    paths: Arc<MarkPaths>,
    sink: Option<NoticeSink>,
    notices: &mut Vec<UidNotice>,
) -> Option<(Sender<u64>, std::thread::JoinHandle<()>)> {
    let (tx, rx) = mpsc::channel::<u64>();
    let spawned = std::thread::Builder::new()
        .name("uid-mark".to_string())
        .spawn(move || {
            loop {
                let outcome = match rx.recv_timeout(TOPUP_INTERVAL) {
                    Ok(target) => store_target(&shared, &paths, target),
                    Err(RecvTimeoutError::Timeout) => top_up(&shared, &paths),
                    Err(RecvTimeoutError::Disconnected) => {
                        // The counter is gone. One last write, so the mark
                        // covers every uid the run handed out rather than only
                        // the reservation it last asked for.
                        if let Err(e) = top_up(&shared, &paths) {
                            declare_write_failure(&paths, &shared, &e, sink.as_ref());
                        }
                        return;
                    }
                };
                if let Err(e) = outcome {
                    declare_write_failure(&paths, &shared, &e, sink.as_ref());
                    // `extending` is left set and the thread returns: a wedged
                    // disk must not be retried once per session for the rest of
                    // the run. The degradation is declared once and the run
                    // continues issuing uids from memory.
                    return;
                }
            }
        });

    match spawned {
        Ok(handle) => Some((tx, handle)),
        Err(e) => {
            notices.push(UidNotice::degraded(format!(
                "cannot start the session-uid mark writer: {e} — the reservation of {LEASE} uids \
                 stands, but it will not be extended"
            )));
            None
        }
    }
}

/// The largest value this boot will believe, from a mark or from a journal.
///
/// Two things bound a uid. The archive cannot carry one past
/// [`MAX_EXACT_UID`] without losing it, and a `u64` corrupted upwards wraps the
/// counter — which hands out duplicates *inside* one run and leaves a mark no
/// later boot can climb past, a permanent wedge from a single bad value.
///
/// The bound is deliberately not "a little above the clock", tempting as that
/// is. A host whose RTC has died reads 1970 or 2000 while its mark legitimately
/// holds 2027, and rejecting the mark there would reissue the exact range the
/// mark exists to protect — the failure this module was written for. So the
/// ceiling is what the archive can express, and it follows the clock only on a
/// host whose own clock has passed that point.
fn uid_ceiling(clock_us: u64) -> u64 {
    MAX_EXACT_UID.max(clock_us)
}

/// Decide where this boot's range begins.
fn resolve_start(
    clock_us: u64,
    dir: &Path,
    paths: &MarkPaths,
    notices: &mut Vec<UidNotice>,
) -> u64 {
    let ceiling = uid_ceiling(clock_us);
    match read_mark(&paths.mark) {
        Ok(Some(persisted)) if persisted > ceiling => {
            // Refusing costs the previous range, which is why it is declared —
            // but adopting the value costs every future range as well.
            notices.push(UidNotice::degraded(format!(
                "mark {persisted} in {} is past {ceiling}, the largest uid this archive can \
                 carry — not adopted, and replaced; uids from {clock_us} may collide with an \
                 earlier run's",
                paths.mark.display()
            )));
            clock_us
        }
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
        Ok(None) => {
            let (found, coverage) = scan_journals_for_max_uid(dir, ceiling, notices);
            match found {
                // A floor derived from journals that were read end to end. It
                // is the highest uid the files *record*, which is not the same
                // claim as the highest uid ever issued — a uid reaches a
                // journal through a bounded queue and a buffered writer — so
                // the notice says which one it is.
                Some(max) if coverage.complete() => {
                    let start = clock_us.max(max.saturating_add(1));
                    notices.push(UidNotice::warn(
                        "session_uid_bootstrap",
                        format!(
                            "no {} yet; scanned the journals in {}, highest uid recorded there \
                             {max}, first uid {start}",
                            MARK_FILE,
                            dir.display()
                        ),
                    ));
                    start
                }
                Some(max) => {
                    let start = clock_us.max(max.saturating_add(1));
                    notices.push(UidNotice::degraded(format!(
                        "no {MARK_FILE}, and the journals in {} were not read in full ({}); the \
                         highest uid recorded in what could be read is {max}, so uids from \
                         {start} may collide with an earlier run's",
                        dir.display(),
                        coverage.describe()
                    )));
                    start
                }
                // Nothing recovered. Whether that means a new host or a floor
                // this boot could not establish is the whole question: the
                // collector creates its journals at every boot, so their
                // presence proves nothing, but a journal holding records does.
                None if coverage.saw_records() => {
                    notices.push(UidNotice::degraded(format!(
                        "no {MARK_FILE}, and the journals in {} yielded no uid ({}); an earlier \
                         run's range cannot be established, so uids from {clock_us} may collide \
                         with it",
                        dir.display(),
                        coverage.describe()
                    )));
                    clock_us
                }
                None => {
                    notices.push(UidNotice::info(
                        "session_uid_fresh",
                        format!(
                            "no {MARK_FILE} and no journal in {} holding a record; first uid \
                             {clock_us}",
                            dir.display()
                        ),
                    ));
                    clock_us
                }
            }
        }
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

/// What one bootstrap scan managed to read.
///
/// The floor it produces is only worth as much as its coverage: a generation
/// that exists and was not read end to end can hold uids above everything the
/// scan saw, and a boot that starts below those reissues them.
#[derive(Default)]
struct ScanCoverage {
    /// Generations holding records that were read to the end.
    read: usize,
    /// Generations holding records that were not, each with its reason.
    unread: Vec<String>,
}

impl ScanCoverage {
    fn complete(&self) -> bool {
        self.unread.is_empty()
    }

    /// Whether any journal held bytes at all. The collector opens all four at
    /// every boot, so an empty one is a file it created, not a history.
    fn saw_records(&self) -> bool {
        self.read > 0 || !self.unread.is_empty()
    }

    fn describe(&self) -> String {
        if self.unread.is_empty() {
            format!("{} generation(s) read, none holding a uid", self.read)
        } else {
            self.unread.join("; ")
        }
    }
}

/// One-time recovery for a host that has journals but no mark.
///
/// Only reached on the boot that introduces the mark file. Every later boot
/// reads the mark and never touches the journals.
fn scan_journals_for_max_uid(
    dir: &Path,
    ceiling: u64,
    notices: &mut Vec<UidNotice>,
) -> (Option<u64>, ScanCoverage) {
    let mut max: Option<u64> = None;
    let mut coverage = ScanCoverage::default();
    for name in JOURNALS {
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
            coverage
                .unread
                .push(format!("{} is past the scan bound", path.display()));
            continue;
        }
        let file = match File::open(&path) {
            Ok(f) => f,
            Err(e) => {
                notices.push(UidNotice::degraded(format!(
                    "cannot scan {} for a previous uid range: {e}",
                    path.display()
                )));
                coverage
                    .unread
                    .push(format!("cannot open {}: {e}", path.display()));
                continue;
            }
        };

        let mut unreadable = 0usize;
        let mut implausible = 0usize;
        let mut gave_up = false;
        for line in BufReader::new(file).lines() {
            let line = match line {
                Ok(l) => l,
                Err(_) => {
                    // A line that is not UTF-8 is a line, not the end of the
                    // file: the journal is append-only, so the uids that matter
                    // most are the newest and they sit after it.
                    unreadable += 1;
                    if unreadable > MAX_UNREADABLE_LINES {
                        gave_up = true;
                        break;
                    }
                    continue;
                }
            };
            let Ok(value) = serde_json::from_str::<serde_json::Value>(&line) else {
                continue;
            };
            if let Some(uid) = value.get("session_uid").and_then(serde_json::Value::as_u64) {
                if uid > ceiling {
                    // Adopted, this would seed the counter past the point the
                    // archive can express and wrap it — the same wedge a
                    // corrupted mark causes, arriving through a different file.
                    implausible += 1;
                    continue;
                }
                max = Some(max.map_or(uid, |m| m.max(uid)));
            }
        }

        let mut trouble = Vec::new();
        if gave_up {
            trouble.push(format!(
                "{} stopped after {unreadable} unreadable lines",
                path.display()
            ));
        } else if unreadable > 0 {
            // Named rather than folded into the finding: the uids on those
            // lines are the ones the floor cannot account for.
            notices.push(UidNotice::warn(
                "session_uid_bootstrap",
                format!(
                    "{unreadable} unreadable line(s) skipped in {}",
                    path.display()
                ),
            ));
        }
        if implausible > 0 {
            trouble.push(format!(
                "{} holds {implausible} uid(s) past {ceiling}",
                path.display()
            ));
        }
        if trouble.is_empty() {
            coverage.read += 1;
        } else {
            coverage.unread.push(trouble.join(", "));
        }
    }
    (max, coverage)
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

    /// A uid is minted at accept and written to `events.jsonl` there and then;
    /// the `sessions.jsonl` record is written at close. Every session that was
    /// alive when the daemon died therefore left its uid in the events journal
    /// and in no other, so a scan that reads only the session journal recovers
    /// a floor below uids that already key marks and a window series.
    #[test]
    fn uids_recorded_only_at_session_open_still_raise_the_floor() {
        let dir = tmpdir("open-only");
        std::fs::write(
            dir.join("sessions.jsonl"),
            "{\"session_uid\":1800000000000001,\"listener\":\"udp\"}\n\
             {\"session_uid\":1800000000000002,\"listener\":\"udp\"}\n",
        )
        .expect("write");
        // Three sessions that never closed: open in the events journal, absent
        // from the session journal.
        std::fs::write(
            dir.join("events.jsonl"),
            "{\"kind\":\"session_open\",\"session_uid\":1800000000000003}\n\
             {\"kind\":\"session_open\",\"session_uid\":1800000000000004}\n\
             {\"kind\":\"session_open\",\"session_uid\":1800000000000005}\n",
        )
        .expect("write");
        std::fs::write(
            dir.join("events.jsonl.1"),
            "{\"kind\":\"session_open\",\"session_uid\":1800000000000006}\n",
        )
        .expect("write");

        // A clock far below the recorded uids, so only the scan can save it.
        let (c, notices) = SessionUidCounter::open(7, &dir);
        assert_eq!(
            c.next(),
            1_800_000_000_000_007,
            "the floor must clear every uid the journals hold, not only the closed ones: {notices:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The scan's own notice must not present what it found as the highest uid
    /// ever issued: it is the highest one that reached a journal, which is a
    /// different claim and the only one the files support.
    #[test]
    fn the_bootstrap_notice_says_where_its_number_came_from() {
        let dir = tmpdir("bootstrap-wording");
        std::fs::write(dir.join("events.jsonl"), "{\"session_uid\":4242}\n").expect("write");
        let (_, notices) = SessionUidCounter::open(7, &dir);
        let n = notices
            .iter()
            .find(|n| n.kind == "session_uid_bootstrap")
            .expect("the recovery must be declared");
        assert!(
            n.detail.contains("recorded"),
            "the notice must name its number as what the journals recorded, got {:?}",
            n.detail
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The collector creates its journals on every boot, so their presence is
    /// not evidence of anything — but their *contents* are. A boot that finds
    /// records it could not turn into a floor has not established one, and
    /// saying "no prior sessions" there asserts the opposite of what it knows.
    #[test]
    fn journals_holding_records_but_no_uid_are_not_called_a_fresh_host() {
        let dir = tmpdir("nofloor");
        // What a daemon killed early leaves: the session journal created and
        // never written to, and an events journal holding the start record.
        std::fs::write(dir.join("sessions.jsonl"), "").expect("write");
        std::fs::write(
            dir.join("events.jsonl"),
            "{\"kind\":\"start\",\"session_uid\":null,\"detail\":\"build=x\"}\n",
        )
        .expect("write");

        let (_, notices) = SessionUidCounter::open(7, &dir);
        assert!(
            notices.iter().any(|n| n.level == UidLevel::Degraded),
            "a boot that could not establish a floor must say so: {notices:?}"
        );
        assert!(
            !notices.iter().any(|n| n.kind == "session_uid_fresh"),
            "and must not assert there were no prior sessions: {notices:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A journal past the scan bound is skipped, which is the right trade —
    /// but the boot that skipped it does not know its own floor, and that is
    /// the record an operator greps for, not an Info saying the host is new.
    #[test]
    fn an_unscanned_journal_leaves_the_boot_degraded_rather_than_fresh() {
        let dir = tmpdir("huge-degraded");
        let path = dir.join("events.jsonl");
        {
            let mut f = File::create(&path).expect("create");
            f.write_all(b"{\"session_uid\":1800000000009999}\n")
                .expect("write");
            f.set_len(BOOTSTRAP_SCAN_MAX_BYTES + 1).expect("set_len");
        }
        let (_, notices) = SessionUidCounter::open(7, &dir);
        assert!(
            notices.iter().any(|n| n.level == UidLevel::Degraded),
            "an unread journal leaves the range unguaranteed: {notices:?}"
        );
        assert!(
            !notices.iter().any(|n| n.kind == "session_uid_fresh"),
            "and must not be reported as no prior sessions: {notices:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The counterweight to the two tests above: a host that really is new
    /// still says so, or the degraded record stops meaning anything.
    #[test]
    fn a_directory_with_no_journal_records_is_reported_fresh() {
        let dir = tmpdir("really-fresh");
        // The four files the collector opens at every boot, all still empty.
        for name in [
            "sessions.jsonl",
            "events.jsonl",
            "snapshots.jsonl",
            "windows.jsonl",
        ] {
            std::fs::write(dir.join(name), "").expect("write");
        }
        let (c, notices) = SessionUidCounter::open(1_800_000_000_000_000, &dir);
        assert_eq!(c.next(), 1_800_000_000_000_000);
        assert!(
            notices.iter().any(|n| n.kind == "session_uid_fresh"),
            "an empty data directory is a fresh one: {notices:?}"
        );
        assert!(
            !notices.iter().any(|n| n.level == UidLevel::Degraded),
            "and nothing about it is degraded: {notices:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A mark is a number this process did not produce this run, and one bad
    /// value must not be permanent. Adopting `u64::MAX` wraps the counter —
    /// duplicates inside a single run — and no later boot can climb past it.
    #[test]
    fn a_mark_past_what_the_archive_can_carry_is_refused_and_declared() {
        let dir = tmpdir("ceiling");
        std::fs::write(dir.join(MARK_FILE), format!("{}\n", u64::MAX)).expect("write");

        let (c, notices) = SessionUidCounter::open(1_800_000_000_000_000, &dir);
        let uids: Vec<u64> = (0..4).map(|_| c.next()).collect();
        assert!(
            uids.windows(2).all(|w| w[0] < w[1]),
            "the counter must not wrap: {uids:?}"
        );
        assert!(
            uids.iter().all(|u| *u < MAX_EXACT_UID),
            "every uid must stay in the range the archive carries exactly: {uids:?}"
        );
        assert!(
            notices.iter().any(|n| n.level == UidLevel::Degraded),
            "refusing a mark costs the previous range and must be declared: {notices:?}"
        );

        // And the wedge is not permanent: the mark now holds a usable number.
        let mark = read_mark(&dir.join(MARK_FILE))
            .expect("readable")
            .expect("rewritten");
        assert_eq!(mark, 1_800_000_000_000_000 + LEASE);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The bootstrap scan adopts a number out of a file with the same trust the
    /// mark gets, so it needs the same ceiling.
    #[test]
    fn a_journal_uid_past_the_ceiling_is_not_adopted() {
        let dir = tmpdir("ceiling-journal");
        std::fs::write(
            dir.join("events.jsonl"),
            format!(
                "{{\"session_uid\":{}}}\n{{\"session_uid\":4242}}\n",
                u64::MAX
            ),
        )
        .expect("write");

        let (c, notices) = SessionUidCounter::open(7, &dir);
        let first = c.next();
        assert!(
            first < MAX_EXACT_UID,
            "a uid the archive cannot carry must not become this run's floor, got {first}"
        );
        assert_eq!(first, 4243, "the usable uid still raises the floor");
        assert!(
            notices.iter().any(|n| n.level == UidLevel::Degraded),
            "a journal holding an impossible uid leaves the floor unguaranteed: {notices:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `BufRead::lines` yields an error for a line that is not UTF-8, and a
    /// journal is append-only: the uids that matter most are the newest, which
    /// sit *after* whatever byte went wrong. Stopping there recovers a floor
    /// below uids already issued and reports it as a finding.
    #[test]
    fn a_line_that_is_not_utf8_does_not_hide_the_uids_after_it() {
        let dir = tmpdir("badbytes");
        let path = dir.join("sessions.jsonl");
        {
            let mut f = File::create(&path).expect("create");
            f.write_all(b"{\"session_uid\":100}\n").expect("write");
            f.write_all(b"\xff\xfe\n").expect("write");
            f.write_all(b"{\"session_uid\":900}\n").expect("write");
        }
        let (c, notices) = SessionUidCounter::open(7, &dir);
        assert_eq!(
            c.next(),
            901,
            "the floor must clear the last uid in the file, not the last one before the bad byte"
        );
        assert!(
            notices.iter().any(|n| n.detail.contains("unreadable")),
            "the skipped bytes must be named, not folded into the finding: {notices:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A failure to extend the mark mid-run is the same failure as a failure to
    /// write it at boot — uids are being handed out that no restart will know
    /// about — and it has to reach the same place. The log alone leaves an
    /// operator following the documented procedure looking at a clean run.
    #[test]
    fn a_mark_that_cannot_be_extended_mid_run_is_declared() {
        let dir = tmpdir("extend-fail");
        let (tx, rx) = mpsc::channel::<UidNotice>();
        let sink: NoticeSink = Arc::new(move |n| {
            let _ = tx.send(n);
        });
        let (c, notices) =
            SessionUidCounter::open_with_sink(1_800_000_000_000_000, &dir, Some(sink));
        assert!(
            notices.iter().all(|n| n.level != UidLevel::Degraded),
            "the boot-time write succeeded: {notices:?}"
        );

        // Wedge the directory only now, so this is unambiguously the run-time
        // arm. A directory under the staging name makes every later write fail
        // for any user, root included — unlike a mode bit, which root ignores.
        std::fs::create_dir_all(dir.join(MARK_TMP_FILE)).expect("mkdir");
        for _ in 0..(LEASE - EXTEND_MARGIN + 1) {
            c.next();
        }

        let n = rx
            .recv_timeout(std::time::Duration::from_secs(30))
            .expect("the run-time failure must be declared, not only logged");
        assert_eq!(n.level, UidLevel::Degraded);
        assert_eq!(
            n.kind, "session_uid_degraded",
            "the kind an operator greps for"
        );
        assert!(
            n.detail.contains(MARK_FILE),
            "the record must name the file it could not write: {}",
            n.detail
        );

        // Releasing the counter tries the same wedged directory once more. A
        // disk that refuses every write must not fill the journal with one
        // machine's fault, so the declaration stands at one.
        drop(c);
        let extra: Vec<UidNotice> = rx.try_iter().collect();
        assert!(
            extra.is_empty(),
            "the degradation is declared once, got {} more: {extra:?}",
            extra.len()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The extension is triggered from `next()`, so the end of a burst leaves
    /// the counter above the mark with nothing left to trigger a write. The
    /// uids in that gap were issued and are not recorded, and a restart on a
    /// clock that has not moved hands them out again.
    #[test]
    fn the_mark_covers_every_uid_issued_once_the_counter_is_dropped() {
        let dir = tmpdir("topup-drop");
        const CLOCK_US: u64 = 1_800_000_000_000_000;
        let (c, _) = SessionUidCounter::open(CLOCK_US, &dir);

        // The state a burst leaves behind, without spending the burst: the
        // counter has run past the reservation the mark on disk covers.
        let past = c.reserved() + 900;
        c.shared.next.store(past, Ordering::Release);
        let highest_issued = past - 1;
        drop(c);

        let mark = read_mark(&dir.join(MARK_FILE))
            .expect("readable")
            .expect("written");
        assert!(
            mark >= highest_issued,
            "the mark {mark} sits below the highest uid issued {highest_issued}"
        );

        let (b, _) = run(CLOCK_US, &dir, 4);
        assert!(
            b[0] > highest_issued,
            "a restart reissued uid {} — already handed out",
            b[0]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The same gap, closed without waiting for a shutdown that a killed
    /// daemon never performs.
    #[test]
    fn the_mark_catches_up_with_the_counter_while_the_run_continues() {
        let dir = tmpdir("topup-tick");
        const CLOCK_US: u64 = 1_800_000_000_000_000;
        let (c, _) = SessionUidCounter::open(CLOCK_US, &dir);

        let past = c.reserved() + 900;
        c.shared.next.store(past, Ordering::Release);

        // Bounded: a mark that never catches up fails the test rather than
        // hanging it.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        let mut mark = 0;
        while std::time::Instant::now() < deadline {
            mark = read_mark(&dir.join(MARK_FILE))
                .expect("readable")
                .expect("written");
            if mark >= past - 1 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        assert!(
            mark >= past - 1,
            "the mark {mark} never caught up with the {} uids handed out",
            past - 1
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
