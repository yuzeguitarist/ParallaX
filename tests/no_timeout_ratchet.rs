//! Static "no new untimed inbound-read loop" ratchet (Phase 3 #5, PART 1).
//!
//! What this guards
//! ----------------
//! ParallaX's documented DoS class is an inbound (client- or origin-facing)
//! `read` inside a `loop {}` / `select!` with no wall-clock bound: a peer that
//! connects, authenticates (or just opens), and then trickles or withholds bytes
//! pins the connection slot, the per-source/global admission permits, and both
//! file descriptors indefinitely. The security review found this shape in the
//! pre-PQ data loop, the relay (upload/download) loops, and their client-side
//! mirrors. Several were since wrapped in `timeout(...)`; the rest are bounded
//! only *structurally* (an external idle-watchdog future raced in a sibling
//! `select!` arm, or a `sleep`/`sleep_until` deadline branch), which a per-read
//! scan cannot see — exactly the cases most at risk of a silent regression.
//!
//! This test does NOT prove the surviving untimed reads are safe. It is a
//! ratchet: it pins TODAY's count of untimed inbound-read sites so that *adding a
//! new one* (a fresh `read` in a loop with no nearby `timeout(`) turns the build
//! RED, forcing the author to either add a timeout or consciously bump the
//! baseline with justification. It is deliberately biased toward catching a gross
//! regression, not toward proving the current tree correct.
//!
//! SCOPE (not whole-tree): this scans only `src/handshake/server.rs` and
//! `src/client/runtime.rs` — the TCP handshake/relay read-loop surface — and
//! only the `read_record_into` / `read_exact` / `.read(` token shapes. An untimed
//! read introduced in another module (e.g. a UDP/QUIC datagram path) or via a
//! different read primitive is OUT of scope and would NOT trip this ratchet; a
//! green build means "no new untimed read of the watched shapes in those two
//! files", not "no new untimed read anywhere".
//!
//! How it works (deterministic static text scan)
//! ---------------------------------------------
//! At test time we `read_to_string` two source files via `CARGO_MANIFEST_DIR`
//! (so no xtask, workspace, or build-graph wiring is needed), restrict to each
//! file's *production* region (everything above its `#[cfg(test)] mod tests`
//! line, so test helpers — which legitimately use bare bounded reads — never
//! inflate the count), and:
//!
//!   1. Find every inbound-read call site: a line containing `read_record_into(`
//!      (excluding the non-blocking `try_read_record_into(`, which returns `None`
//!      on would-block and so cannot hang), `read_exact(`, or `.read(`.
//!   2. Classify each TIMED vs UNTIMED by whether the literal token `timeout(`
//!      or `timeout_at(` appears within a symmetric ±`WINDOW`-line window around
//!      the call. The window is symmetric on purpose: the QUIC teardown reads sit
//!      *inside* a `select!` whose `timeout(...)` wrapper is a few lines *below*
//!      the read (the async block is defined first, then awaited under a
//!      timeout), so a backward-only window would misclassify a genuinely-bounded
//!      read as untimed. `WINDOW` is kept small (6) so a `timeout(` belonging to
//!      an unrelated nearby construct cannot leak into an untimed read's window
//!      (the closest such gap in today's tree is ~31 lines).
//!   3. Count the UNTIMED sites and assert the total equals the pinned baseline.
//!
//! Determinism / flakiness
//! ------------------------
//! Pure function of the two source files' bytes: same source → same counts,
//! every run, on every platform. Whitespace/formatting churn does not change the
//! result (the classifier keys on tokens and a generous line window, not on exact
//! columns). Renaming a variable does not change it. Only adding/removing an
//! inbound-read call site, or moving a `timeout(` into/out of a read's window,
//! moves the numbers — which is precisely the signal we want.
//!
//! If this test goes RED
//! ---------------------
//! * You added a TIMED loop (a read already wrapped in `timeout(`/`timeout_at(`
//!   within the window): the untimed count is unchanged — this test stays GREEN.
//!   If it went red anyway, the total-site or per-file expectations below need a
//!   one-line bump (you added a read site, which is fine).
//! * You added an UNTIMED inbound read in a `loop`/`select!`: either wrap it in a
//!   `timeout(...)` (preferred — closes the DoS), or, if it is provably bounded
//!   another way (an external watchdog you are confident in, an EOF-terminated
//!   bulk read, etc.), consciously bump `EXPECTED_UNTIMED_*` below and add a
//!   one-line justification next to the fingerprint list so the next reader knows
//!   why the count moved.

use std::fs;

/// Symmetric half-window (in lines) searched around each inbound-read call site
/// for a `timeout(` / `timeout_at(` token. Small enough that an unrelated nearby
/// timeout cannot leak in (the tightest untimed-read-to-foreign-timeout gap in
/// the current tree is ~31 lines), large enough to catch the QUIC teardown reads
/// whose `timeout(...)` wrapper sits ~4 lines below the read.
const WINDOW: usize = 6;

/// Untimed inbound-read sites in `src/handshake/server.rs` production code.
///
/// Reflects (top to bottom): the userspace fallback relay's two `select!` reads
/// (bounded by an `idle_sleep` branch, not `timeout(`); the pre-PQ data loop's
/// client- and fallback-reader `select!` arms (bounded by a `sleep_until`
/// deadline branch); the relay-loop reads — `server_upload_loop`'s
/// client read, plus `server_download_loop`'s target reads in its cover-traffic
/// branch AND the three reads of its saturated-gate read-ahead pipeline (the prime
/// read, the `write_batch_with_read_ahead` read-ahead in the saturated branch, and
/// the serial read in the non-saturated branch), each bounded only by the external
/// `relay_idle_watchdog` future raced in a sibling `select!` arm and by the loop's
/// own EOF termination; and the mux-over-QUIC session-end watcher's one-shot TCP
/// read (`run_authenticated_mux_quic_data_mode`): not a relay loop and holds no
/// per-substream resources (each substream has its own `relay_idle_watchdog`), so
/// an unbounded wait here only delays the whole-session end until the QUIC
/// connection's own idle-timeout closes it — no per-read DoS to bound. The
/// substream's ConnectRequest read IS bounded (`PX1_CONTROL_READ_TIMEOUT`) and
/// classifies as TIMED, so it does not appear here.
///
/// +3 vs the prior baseline of 8: `server_download_loop`'s saturated-gate
/// read-ahead pipeline adds a prime read, a `write_batch_with_read_ahead`
/// read-ahead (saturated branch), and a serial read (non-saturated branch). All
/// three are inbound origin reads in the same loop, bounded identically to the
/// loop's other reads (EOF termination + the external `relay_idle_watchdog`), so
/// they are a conscious no-new-DoS bump, not a new untimed DoS surface.
const EXPECTED_UNTIMED_SERVER: usize = 11;

/// Untimed inbound-read sites in `src/client/runtime.rs` production code.
///
/// Reflects: the three handshake reads (UDP-negotiation response read, the
/// key-exchange-after-residuals loop, the server-identity reassembly loop), the
/// `client_upload_loop` reads of the *local* SOCKS app socket (loopback, not
/// network-facing, but matched by the same `.read(` token) — the three reads of its
/// saturated-gate read-ahead pipeline (prime + `write_batch_with_read_ahead`
/// read-ahead in the saturated branch + serial read in the non-saturated branch)
/// plus the cover-traffic branch read — the `client_mux_upload_loop` local read,
/// and `client_download_loop`'s server read — the client-side mirror of the server
/// relay loop, bounded only by `client_relay_idle_watchdog`.
///
/// +2 vs the prior baseline of 7: `client_upload_loop`'s non-cover branch now
/// runs the saturated-gate read-ahead pipeline — its single serial local read is
/// replaced by a prime read, a `write_batch_with_read_ahead` read-ahead (saturated
/// branch), and a serial read (non-saturated branch), a net +2 read sites. All are
/// loopback reads bounded by the loop's EOF termination and the external
/// `client_relay_idle_watchdog`, so this is a conscious no-new-DoS bump.
const EXPECTED_UNTIMED_RUNTIME: usize = 9;

/// One classified inbound-read call site.
struct ReadSite {
    /// 1-based line number in the source file (for diagnostics).
    line: usize,
    /// Whether a `timeout(`/`timeout_at(` token was found within ±WINDOW lines.
    timed: bool,
    /// The trimmed source line, used as a human-readable fingerprint so a diff
    /// in the failure output points at the exact call that moved the count.
    fingerprint: String,
}

/// Read a production source file relative to the crate root, returning only the
/// region above its `#[cfg(test)] mod tests` declaration. Test helpers below that
/// boundary legitimately use bare bounded reads and must not be scanned.
fn read_production_region(relative_path: &str) -> Vec<String> {
    let full_path = format!("{}/{}", env!("CARGO_MANIFEST_DIR"), relative_path);
    let source = fs::read_to_string(&full_path)
        .unwrap_or_else(|e| panic!("failed to read {full_path}: {e}"));
    let lines: Vec<String> = source.lines().map(str::to_owned).collect();

    // Find the `mod tests {` that follows a `#[cfg(test)]` attribute — the start
    // of the in-file unit-test module. Everything from there down is excluded.
    let boundary = lines
        .iter()
        .position(|l| l.trim_start().starts_with("mod tests"))
        .unwrap_or_else(|| {
            panic!(
                "{relative_path}: could not locate `mod tests` boundary; \
                    the scan must exclude the in-file test module"
            )
        });

    lines.into_iter().take(boundary).collect()
}

/// Does this line contain a blocking inbound-read call we care about?
///
/// Matches `read_record_into(`, `read_exact(`, and `.read(`. Excludes the
/// non-blocking `try_read_record_into(` (it returns `None` on would-block and so
/// cannot hang). Note `.read(` does not match `.read_record_into(` (the latter
/// has `_` after `read`, not `(`), so there is no double counting between the two
/// token families.
fn read_call_count(line: &str) -> usize {
    let mut count = 0;

    // `read_record_into(` occurrences that are NOT `try_read_record_into(`.
    let mut search_from = 0;
    while let Some(idx) = line[search_from..].find("read_record_into(") {
        let abs = search_from + idx;
        let preceded_by_try = line[..abs].ends_with("try_");
        if !preceded_by_try {
            count += 1;
        }
        search_from = abs + "read_record_into(".len();
    }

    count += line.matches("read_exact(").count();
    count += line.matches(".read(").count();
    count
}

/// Scan a production region for inbound-read sites and classify each TIMED vs
/// UNTIMED by `timeout(`/`timeout_at(` proximity within ±WINDOW lines.
fn scan_read_sites(lines: &[String]) -> Vec<ReadSite> {
    let mut sites = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        let hits = read_call_count(line);
        if hits == 0 {
            continue;
        }
        let lo = i.saturating_sub(WINDOW);
        let hi = (i + WINDOW + 1).min(lines.len());
        let window = lines[lo..hi].join("\n");
        let timed = window.contains("timeout(") || window.contains("timeout_at(");
        // A single line could in principle hold two read calls; record one site
        // per call so the count is exact. They share the same classification and
        // fingerprint (same enclosing window).
        for _ in 0..hits {
            sites.push(ReadSite {
                line: i + 1,
                timed,
                fingerprint: line.trim().chars().take(80).collect(),
            });
        }
    }
    sites
}

/// Render the classified sites as a stable, greppable block for failure output.
fn render(label: &str, sites: &[ReadSite]) -> String {
    let mut out = format!("--- {label} ---\n");
    for s in sites {
        let tag = if s.timed { "TIMED  " } else { "UNTIMED" };
        out.push_str(&format!("  L{:<5} {}  {}\n", s.line, tag, s.fingerprint));
    }
    out
}

/// Core assertion shared by both files: pin the untimed count and self-check the
/// classifier for non-vacuity (it must find reads at all, and must classify at
/// least one as TIMED — otherwise a broken classifier that saw nothing, or
/// labelled everything untimed, would pass trivially).
fn assert_ratchet(label: &str, relative_path: &str, expected_untimed: usize) {
    let lines = read_production_region(relative_path);
    let sites = scan_read_sites(&lines);

    let total = sites.len();
    let timed = sites.iter().filter(|s| s.timed).count();
    let untimed = total - timed;
    let report = render(label, &sites);

    // Non-vacuity #1: the scan must actually find inbound reads. If this fires,
    // the read APIs were renamed (e.g. `read_record_into` -> something else) and
    // `read_call_count` needs updating — the ratchet is silently disarmed
    // otherwise.
    assert!(
        total > 0,
        "{label}: found zero inbound-read sites — the read-API tokens are stale \
         and this ratchet is disarmed. Update `read_call_count`.\n{report}"
    );

    // Non-vacuity #2: at least one site must classify as TIMED. If everything is
    // untimed, the `timeout(`/`timeout_at(` detection (or the window) is broken
    // and every future untimed read would be invisible against the baseline.
    assert!(
        timed > 0,
        "{label}: classifier found NO timed reads — the `timeout(` detection or \
         the ±{WINDOW}-line window is broken; the ratchet cannot distinguish a \
         new untimed read.\n{report}"
    );

    // The ratchet itself: a new untimed inbound read in a loop/select raises this
    // count. See the module header for what to do if this fires.
    assert_eq!(
        untimed, expected_untimed,
        "{label}: untimed inbound-read count changed ({untimed}, baseline \
         {expected_untimed}). If you ADDED an untimed read in a loop/select, add \
         a `timeout(...)` (preferred) or consciously bump the baseline with \
         justification. If you added a TIMED read, this baseline is unchanged — \
         adjust only the total-site self-check.\n{report}"
    );
}

/// Server handshake/relay path: pre-PQ loop, fallback relay, and the
/// upload/download relay loops.
#[test]
fn server_inbound_reads_have_no_new_untimed_loop() {
    assert_ratchet(
        "server.rs",
        "src/handshake/server.rs",
        EXPECTED_UNTIMED_SERVER,
    );
}

/// Client runtime path: handshake reads and the client-side relay mirror.
#[test]
fn client_inbound_reads_have_no_new_untimed_loop() {
    assert_ratchet(
        "runtime.rs",
        "src/client/runtime.rs",
        EXPECTED_UNTIMED_RUNTIME,
    );
}

/// Combined-tree self-check: pins the aggregate total and timed/untimed split so
/// a change that removed an untimed read from one file while adding one to the
/// other (leaving each per-file count unchanged) is still caught, and so the
/// global "we have inbound reads, and some are timed" invariant is asserted once
/// more over both files together.
#[test]
fn combined_inbound_read_census_is_pinned() {
    let server = scan_read_sites(&read_production_region("src/handshake/server.rs"));
    let runtime = scan_read_sites(&read_production_region("src/client/runtime.rs"));

    let total = server.len() + runtime.len();
    let timed =
        server.iter().filter(|s| s.timed).count() + runtime.iter().filter(|s| s.timed).count();
    let untimed = total - timed;

    // Total inbound-read call sites across both production files today: 23
    // (server) + 12 (runtime) = 35. This catches a *removed* read site too,
    // which would otherwise slip past the per-file untimed-only assertions.
    // (+2 server vs the mux-over-QUIC baseline of 28: the speed QUIC-run request
    // read and the speed QUIC-run TCP DONE read — both TIMED. +5 for the
    // saturated-gate read-ahead pipeline: server_download_loop adds 3 (it keeps the
    // serial cover-traffic read, then adds prime + saturated read-ahead + the
    // non-saturated serial read), and client_upload_loop adds a net 2 (its serial
    // no-cover read is replaced by prime + saturated read-ahead + non-saturated
    // serial read) — all UNTIMED, all in their existing relay loops.)
    // (+2 server vs the prior baseline of 35: the FIN-first teardown drain adds two
    // reads — `graceful_fin_then_drain` and `graceful_fin_then_drain_stream` — each
    // a `read()` bounded by `timeout_at(GRACEFUL_FIN_DRAIN_BUDGET)`, so both TIMED.)
    const EXPECTED_TOTAL_SITES: usize = 37;
    // Timed sites: 14 (server) + 3 (runtime) = 17. (+2 server vs the prior 15: the
    // two FIN-first drain reads above, both bounded by `GRACEFUL_FIN_DRAIN_BUDGET`.)
    const EXPECTED_TIMED_SITES: usize = 17;

    assert_eq!(
        total, EXPECTED_TOTAL_SITES,
        "combined inbound-read site count changed ({total}, baseline \
         {EXPECTED_TOTAL_SITES}). A read site was added or removed; reconcile \
         with the per-file ratchets and bump this baseline."
    );
    assert_eq!(
        timed, EXPECTED_TIMED_SITES,
        "combined TIMED read count changed ({timed}, baseline \
         {EXPECTED_TIMED_SITES})."
    );
    assert_eq!(
        untimed,
        EXPECTED_UNTIMED_SERVER + EXPECTED_UNTIMED_RUNTIME,
        "combined UNTIMED read count ({untimed}) disagrees with the sum of the \
         per-file baselines ({} + {}).",
        EXPECTED_UNTIMED_SERVER,
        EXPECTED_UNTIMED_RUNTIME
    );
}

/// Self-test of the classifier's mechanics on synthetic input, with no
/// dependence on the real source files. Guards the three subtle behaviors the
/// whole ratchet rests on: (a) `try_read_record_into(` is excluded; (b) a
/// `timeout(` *below* the read (within the window) still classifies it TIMED
/// (the symmetric-window requirement); and (c) a bare read in a loop with no
/// nearby timeout is UNTIMED.
#[test]
fn classifier_mechanics_self_test() {
    // (a) try_ prefix excluded; plain call counted.
    assert_eq!(
        read_call_count("    foo.try_read_record_into(&mut b).await"),
        0
    );
    assert_eq!(read_call_count("    foo.read_record_into(&mut b).await"), 1);
    assert_eq!(read_call_count("    s.read_exact(&mut b).await"), 1);
    assert_eq!(read_call_count("    s.read(&mut b).await"), 1);
    // `.read(` must not match inside `.read_record_into(`.
    assert_eq!(read_call_count("    s.read_record_into(&mut b)"), 1);

    // (b) timeout BELOW the read, within the window -> TIMED.
    let below: Vec<String> = [
        "let done = async {",
        "    select! {",
        "        res = reader.read_record_into(&mut r) => res,",
        "        _ = conn.closed() => Ok(()),",
        "    }",
        "};",
        "let out = timeout(BACKSTOP, done).await;",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    let sites = scan_read_sites(&below);
    assert_eq!(sites.len(), 1);
    assert!(
        sites[0].timed,
        "a timeout() within +WINDOW lines below the read must classify it TIMED"
    );

    // (c) bare read in a loop, no timeout anywhere near -> UNTIMED.
    let untimed: Vec<String> = [
        "loop {",
        "    let n = target_read.read(&mut buf).await?;",
        "    if n == 0 { break; }",
        "    sink.write_all(&buf[..n]).await?;",
        "}",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    let sites = scan_read_sites(&untimed);
    assert_eq!(sites.len(), 1);
    assert!(
        !sites[0].timed,
        "a bare read in a loop with no nearby timeout must classify UNTIMED"
    );
}
