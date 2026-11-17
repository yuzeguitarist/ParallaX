# Protocol state machines

Exhaustive check of the control-state machines that are easy to get wrong:
the TCP session (handshake, PQ rekey, replay, identity, reconnect), the QUIC
TLS handshake order, 0-RTT ticket use, the replay-insert decision, the UDP
probe outcome, the inbound auth gates, QUIC key installation, QUIC close and
drain, the BBR mode graph, and the QUIC first-byte class.
The record-batch and framed-command models add bounded checks of nonce
reservation/failure and repeated PX1F reassembly.
The TCP MUX model checks admission and independent substream lifetimes; a
separate PX1I caller model checks bounded metadata through identity verification
and the CONNECT barrier, including establishment failures.

This is a model of control state, not a byte-level proof of X25519, ML-KEM, or
AEAD. A step such as `AuthOk` stands in for a check the Rust code already
performs. The correspondence check below fails CI if that Rust control flow
moves. [`COVERAGE.md`](COVERAGE.md) lists every `src/**/*.rs` file and says
which slice is exhaustive and which is not. A new Rust file fails `check`
until it is classified there. Whole-program proof of every character is not
what this directory does.

## Run

From the repository root:

```bash
python3 formal/plx_formal.py check        # exhaust the model; prove the never-events
python3 formal/plx_formal.py correspond   # Rust call order still matches the model
python3 formal/plx_formal.py emit         # regenerate formal/*.tla and *.cfg
python3 formal/plx_formal.py tlc --jar /path/to/tla2tools.jar
```

`check` explores every reachable state of the tables in `formal/plx_formal.py`
and fails if a safety formula is false, if a required outcome never happens, or
if a dead end is not an intentional terminal. It also fails when the committed
TLA+ files drift from those tables. Edit the tables, run `emit`, and commit
both.

TLC (TLA+ tools 1.7.4) checks the same formulas with a separate engine. The
`formal` GitHub Actions workflow runs `check`, `correspond`, and TLC. Pull
requests also run the Python tests from the main CI lint job, without Java.

## What must never happen

Each name is an invariant. Both the Python checker and TLC prove it over every
reachable state.

### TCP session (`ParallaXSession`)

Auth failure, a missing SNI, and an unauthorized SNI splice to the camouflage
origin and install no keys. After auth/SNI pass, replay handling has two gates:

1. **Early pending admission:** `handle_connection_inner` calls
   `reserve_pending` before `accept_authenticated_with_origin`. The cache first
   prunes expired entries and checks pending capacity, then checks timestamp
   freshness, committed nonce/transcript, and duplicate pending transcript.
   Refusal, including a busy cache lock, returns `relay_admitted_fallback` and
   installs no epoch-0 keys. Success reserves an in-flight transcript only; it
   does not commit a durable journal entry. An absent optional cache skips this
   reservation and proceeds to the later fail-closed gate.
2. **Late data-proof commit:** only a valid PX1Q reaches
   `commit_pending_replay_entry`. A previously admitted hello can lose a race,
   become stale, hit committed-journal capacity/source quota, or have no cache.
   That refusal takes the jittered close path before `apply_server_pq_rekey`:
   epoch-0 keys already exist, but epoch 1 and the identity binding do not.

Between the gates, `derive_keys_from_shared` rejects a degenerate all-zero
X25519 secret without splicing or installing keys. The same reject in
`hybrid_sandwich_rekey` fails after the late commit without advancing the
epoch. `FallbackReason::Replay` is not constructed; early replay refusal uses
the direct admitted-fallback branch, while late commit refusal closes.

| Invariant | Unreachable situation |
| --- | --- |
| `AppOnlyAfterIdentity` | Application data before identity, or at any epoch other than 1, or with dead keys |
| `VerifiedImpliesBinding` | `verified` / `app` without a PQ identity binding and live epoch-1 keys |
| `RekeyedImpliesFreshCommit` | A rekeyed session whose replay cache insert was not fresh |
| `ReplayClosesBeforeRekey` | A late replay/stale/full/source-quota/missing-cache refusal splices or promotes the session past epoch 0 |
| `PendingRefusalSplicesWithoutKeys` | An early pending refusal installs epoch-0 keys or takes the later close branch |
| `EpochZeroRequiresAdmission` | Session keys exist without passing the early pending gate or its optional-cache-missing branch |
| `AdmittedStillHasNoKeys` | Pending admission itself installs keys before the shared-secret check |
| `IdleAndReconnectAreFresh` | A reconnect that keeps the previous epoch, binding, keys, UDP leg, or failure class |
| `AuthedHasNoKeys` | Authentication that has already installed epoch-0 keys |
| `PostAuthDegenerateDoesNotSplice` | An all-zero shared secret after auth that splices or installs keys |
| `RekeyDegenerateStaysAtEpochZero` | An all-zero rekey ephemeral that advances the epoch or splices |
| `SpliceIsTheInboundReject` | An auth/SNI or early pending fallback splice after keys exist |
| `TerminalDropsUsableKeys` | Sealing or sending application data after reject, close, or failure |
| `UdpRetainOnlyAfterApp` | Retaining the QUIC leg before the session is in the live app phase |
| `UdpDeclineStaysOnApp` | A failed UDP probe dropping the already-verified TCP session |
| `UsableKeysImplyAuth` | Usable keys with no successful auth, including back in `idle` |
| `EpochIsZeroOrOne` | An epoch outside `{0, 1}` (rekey steps by exactly one) |
| `RejectedOnlyAfterReplay` | The rejected phase from anything other than a replay-cache refusal |
| `BindingMeansRekeyedEpoch` | An identity binding at epoch 0, or without a fresh replay insert |
| `AttemptInBounds` | A reconnect past the bounded third attempt |

Both cipher directions rekey in one action. The Rust side of that assumption
is the pair of `rekey_with_suite` calls inside `apply_pq_rekey_shared` and
`apply_server_pq_rekey`, which the correspondence check requires to stay
together and ahead of the identity binding.

### QUIC TLS handshake (`ParallaXQuic`)

The client `ReadState` machine and the server `ServerState` machine. The model
lets the two sides advance alone, so it over-approximates the wire. An
unexpected message before completion alerts and does not set `complete`.
After completion, a non-ticket message alerts and leaves `complete` set.
The server sets `handshake_complete` and only then issues the session ticket.

| Invariant | Unreachable situation |
| --- | --- |
| `CompleteOnlyAfterFinished` | Client completion without `Finished`, or after an alert |
| `ServerCompleteOnlyAfterBothMessages` | Server completion without ClientHello and Finished |
| `ResumptionSkipsCertificate` | A PSK resumption that still went through Certificate |
| `FullHandshakeSeesCertificate` | A full handshake that completed without Certificate and CertificateVerify |
| `AlertBeforeCompleteIsNotSuccess` | An alert before completion that is also a successful client handshake |
| `AlertAfterCompleteDoesNotUndo` | An alert after completion that clears the client handshake |
| `ServerAlertIsNotComplete` | An alert before completion that is also a successful server handshake |
| `ServerAlertAfterCompleteDoesNotUndo` | An alert after completion that clears the server handshake |
| `VerifyFollowsCertificate` | CertificateVerify recorded with no Certificate |
| `PskNeverEntersCertificate` | A resumption sitting in the Certificate states |
| `TicketOnlyAfterComplete` | A NewSessionTicket stored before the handshake completes |
| `ServerTicketOnlyAfterComplete` | A server session ticket issued before `handshake_complete` |
| `ServerNoStekIssuesNoTicket` | A no-STEK server that queues a NewSessionTicket |
| `PostAlertFollowsTheTicketCall` | A post-completion alert that skips `issue_session_ticket`, or a no-STEK server that queued a ticket first |

### 0-RTT and reconnect (`ParallaXZeroRtt`)

One ticket identity. The client consumes it on offer. The server consults the
guard only after the binder matches. `busy` is a contended lock; `out` is the
cache checked out for a persist. Both fail closed: early data is not accepted
and the ticket is not burned. CacheFull and an 8-byte nonce prefix collision
are decided under a free lock and do not burn the ticket. After a fresh
accept the background persist checks the cache out. A second offer in that
window fails closed and does not look like a replay. The journal fsync is
deferred; a restart before it can accept the ticket again.
`AcceptsAtMostOnce` counts one boot, not a crash before that fsync. A second
offer of an accepted ticket is a replay. Relay bytes wait for the handshake,
a verified probe, and Safari SETTINGS.
QUIC retain and the next stored ticket wait for a verified probe and Safari
SETTINGS. A verified probe that fails SETTINGS stores nothing. `dead` is a
handshake timeout; it drops the attempt.

| Invariant | Unreachable situation |
| --- | --- |
| `EarlyDataRequiresFreshAccept` | Accepted early data without a good binder, a free guard, and a first-time insert |
| `FailClosedDoesNotBurnOrAccept` | A busy or checked-out guard accepting 0-RTT or burning the ticket |
| `BadBinderDoesNotBurnOrAccept` | A bad binder burning the ticket or accepting early data |
| `AcceptsAtMostOnce` | A second accept in the same boot. A crash before fsync is a new boot |
| `DurableAcceptStaysBurned` | A durable journal whose accept was cleared, or whose cache is still checked out |
| `CheckoutIsUndurableAccept` | A checked-out cache with no fresh accept, or after fsync |
| `CheckoutRejectsTheConcurrentOffer` | A second offer during checkout that is accepted again |
| `RestartUndoesUndurableAccept` | A pre-fsync restart that leaves the ticket burned or the cache checked out |
| `FullOrClashDoesNotBurn` | CacheFull or a nonce-prefix collision that burns the ticket |
| `RelayWaitsForHandshake` | Relay bytes before the handshake, before a verified probe and Safari SETTINGS, or on a timed-out attempt |
| `RetainOnlyVerified` | A retained QUIC leg without a verified probe |
| `StoreTicketOnlyVerified` | Storing the next resumption ticket without a verified probe and Safari SETTINGS |
| `SettingsFailDoesNotStore` | A verified probe that fails SETTINGS and still stores or retains |
| `VerifiedProbeImpliesHandshake` | A verified probe with the handshake unfinished |
| `ReplayDoesNotAcceptAgain` | A replay marked rejected without a single prior accept |
| `DeadDropsTheAttempt` | A timed-out attempt that still relays, retains, or stores a ticket |
| `DecidedImpliesOffered` | The server deciding a ticket the client has not consumed |
| `HandshakeFollowsEarlyProbe` | Completing this 0-RTT path without the early probe |

### Replay insert (`ParallaXReplay`)

One slot, or protection off (capacity 0). Two abstract handshakes. The model
stops after two decisions. It is the order in `stage_insert` after prune:
stale, then nonce, then transcript rollback, then capacity rollback. Expiry
deletes the slot. A past-window timestamp and a timestamp more than 5 seconds
in the future are Stale, not Replayed. The window edge and a +5 second skew
are fresh. A transcript clash is Replayed, not CacheFull. It is not the
journal MAC and not every nonce.

| Invariant | Unreachable situation |
| --- | --- |
| `OffStoresNothing` | Protection off occupying the slot |
| `SlotIsPaired` | A slot that is not empty, `a/ta`, or `b/tb` |
| `InsertRecordsTheCandidate` | An insert that does not write the candidate |
| `StaleIsNotAReplay` | A stale candidate reported as a replay, including when its nonce is already stored |
| `StaleCannotTakeReplay` | A past-window or future-skewed timestamp classified as Replayed |
| `PastAndFutureAreStale` | A decided past-window or +6s timestamp that is not Stale |
| `EdgeAndSkewAreFresh` | A window-edge or +5s timestamp classified as anything but Replayed when the nonce is stored |
| `ReplayDoesNotRecord` | A replay that writes the slot |
| `ClashIsNotFull` | A transcript clash labeled CacheFull |
| `FullDoesNotEvict` | CacheFull replacing the fresh occupant or storing the candidate |
| `ProtectionOffIsInsert` | Protection off returning stale, replay, or full |
| `ExpireClearsTheSlot` | Time passing that keeps an expired entry in the slot |

### UDP probe (`ParallaXProbe`)

Timeout and connection loss are Unreachable. A setup failure, a short reply,
a bad magic, a bad MAC, or a long body is Failed. There is no separate error
status on the wire. Only the length-and-magic-and-MAC chain is Verified, and
that is the client classifier. The server retains QUIC for an AEAD-opened
PX1P ack whose offer_id matches and whose status byte is Verified, while it
still holds the connection. It does not check its own probe result. A
mismatched offer_id or a decode failure stays on TCP. A PX1P read timeout or
EOF aborts. The status byte (0, 1, 2, and the other 253 values) is exhausted
by `check_probe_status_bytes` from the Rust `match`, not by TLC.

| Invariant | Unreachable situation |
| --- | --- |
| `VerifiedOnlyIfAuthentic` | Verified from anything but an authentic reply |
| `BadMacIsFailed` | A bad exporter MAC classified as Verified or Unreachable |
| `TimeoutIsUnreachable` | A Happy-Eyeballs timeout that is not Unreachable |
| `LostConnectionIsUnreachable` | A lost connection classified as an authentication failure |
| `ShortReplyIsFailed` | A short reply classified as anything but Failed |
| `LongBodyIsFailed` | A long body classified as anything but Failed |
| `SetupIsFailed` | A setup failure classified as anything but Failed |
| `RetainOnlyMatchingAck` | Retaining QUIC without a matching Verified PX1P ack and a held connection |
| `VerifiedWithoutConnHardFails` | A matching Verified ack with no connection taking any branch but hard-fail |
| `MismatchStaysOnTcp` | A mismatched offer_id that retains QUIC |
| `VerifiedStayIsARejectedAck` | Staying on TCP after Verified for a reason other than offer mismatch or decode failure |
| `Px1pTimeoutAborts` | A PX1P read timeout that stays on TCP |
| `Px1pEofAborts` | A PX1P read EOF that stays on TCP |

### Inbound gates (`ParallaXInbound`)

Auth, then SNI presence, then authorization. Replay is not a result of this
decision function; its surrounding early pending-admission gate is part of
`ParallaXSession`. The constant-time DH ballast is not a state.

| Invariant | Unreachable situation |
| --- | --- |
| `MissingSniOnlyAfterAuth` | Missing SNI reported for a record that did not authenticate |
| `UnauthorizedOnlyAfterSni` | An unauthorized-name result without a present name after auth |
| `AuthenticatedClearsEveryGate` | The authenticated branch with a failed gate |
| `AuthFailIsNotASniDecision` | An auth failure that is really a SNI decision |

### QUIC key installation (`ParallaXKeys`)

The order `write_handshake` emits key changes. Distinct from `ParallaXQuic`,
which is the read-state order. Key bytes are not modeled.

| Invariant | Unreachable situation |
| --- | --- |
| `ClientZeroRttOnlyIfOffered` | Client 0-RTT keys without an offered ticket |
| `ServerZeroRttOnlyIfAccepted` | Server 0-RTT keys without accepted early data |
| `AcceptImpliesOffer` | The server accepting early data the client did not offer |
| `ClientHandshakeKeysBeforeOneRtt` | Client 1-RTT keys without Handshake keys |
| `ServerHandshakeKeysBeforeOneRtt` | Server 1-RTT keys without Handshake keys |
| `OfferedZeroRttBeforeHandshakeKeys` | An offered ticket reaching Handshake keys without installing 0-RTT |
| `AcceptedZeroRttBeforeServerHello` | Accepted early data emitting ServerHello before 0-RTT keys |
| `FullHandshakeSkipsZeroRtt` | A full handshake that still installed 0-RTT keys |
| `TicketOnlyAfterServerOneRtt` | A NewSessionTicket phase before server 1-RTT keys |
| `NoStekEmitsNoTicket` | A no-STEK server that emits a NewSessionTicket |
| `NoKeysBeforeClientHello` | Client keys in the initial phase |

### QUIC close (`ParallaXClose`)

One local CONNECTION_CLOSE, including a close packet sent after the drain
timer when it had not been sent yet. None for a peer close or an idle
timeout. After close, application data, STREAM, ACK, and probe sends do not
happen. The peer-close arm does not call `close`. Timers are events.

| Invariant | Unreachable situation |
| --- | --- |
| `OpenHasNoClose` | An open connection that already has a close reason or close packet |
| `ClosePacketOnlyForLocal` | A close packet for a peer or idle close |
| `PeerCloseIsSilent` | A peer close that sends a CONNECTION_CLOSE |
| `IdleCloseIsSilent` | An idle timeout that sends a CONNECTION_CLOSE |
| `TransmitAfterCloseIsTheClosePacket` | Application data, STREAM, ACK, or a probe transmitted after close |
| `DrainedHasAReason` | Draining without a local, peer, or idle reason |

### BBR mode (`ParallaXBbr`)

Startup, ProbeBW, and ProbeRTT. Three quiet rounds fill the pipe and enter
ProbeBW at gain phase 2. A zero sample does not count as a quiet round,
because `full_bw` starts at 0. ProbeRTT does not start on the ack that fills
the pipe. Loss does not change the mode. The window in bytes is not modeled.
The mode has no terminal state; a stuck state fails `check`.

| Invariant | Unreachable situation |
| --- | --- |
| `StartupIsUnfilled` | Startup with a full pipe, a quiet count of 3, or a gain phase in use |
| `ProbeBwMeansFull` | ProbeBW before the pipe has filled |
| `ProbeRttMeansFull` | ProbeRTT before the pipe has filled, or on the ack that filled it |
| `ZeroSampleDoesNotCount` | A zero bandwidth sample that advances the quiet count or leaves Startup |
| `PhaseInCycle` | A gain index outside 0..7 |
| `QuietInBounds` | A quiet count outside 0..3 |

### QUIC first byte (`ParallaXPacket`)

Seven header classes. TLC checks those classes. `check_packet_bytes` reads
the masks from `packet.rs` and classifies all 256 first bytes against the
same table: 128 clear fixed bits, 64 short headers, and 16 of each long type.
Connection IDs and packet numbers are not in the model.

| Invariant | Unreachable situation |
| --- | --- |
| `ShortHeaderIsOneRtt` | A short header in any space but 1-RTT, or 1-RTT from another class |
| `LongTypesMatchTheirSpace` | Initial, 0-RTT, or Handshake mapped to a different space |
| `RetryIsNotASpace` | Retry treated as a decryptable space |
| `ClearFixedBitIsNotASpace` | A clear fixed bit treated as a packet space |
| `EmptyIsNotASpace` | An empty datagram treated as a packet space |
| `ZeroRttIsItsOwnSpace` | 0-RTT classified as 1-RTT or Initial |
| `NoneOnlyForRejects` | A no-space result for a header that should select a space |

## Speed

Formulas are compiled once per check. TLC still checks every invariant, with
`-deadlock`, one worker per spec, and one JVM per spec started together.
`-XX:TieredStopAtLevel=1` and a 256 MB heap cut startup only; they do not
change the spec. Wall times below are `/usr/bin/time -p` real seconds on this
worktree (Apple silicon, Temurin 25, Python 3.14). `check` and `correspond`
were three runs, and each command landed on the same tenth of a second every
time. The TLC after numbers are two warm runs. They include process startup.
They are not a claim that a cold JVM finishes in one second.

| Command | Before | After |
| --- | --- | --- |
| `python3 formal/plx_formal.py check` | 0.06s, three machines, three runs | 0.06s, ten machines plus the ledger and the byte sweeps |
| `python3 formal/plx_formal.py correspond` | 0.04s, three runs | 0.05s, three runs (six more Rust files) |
| `python3 formal/plx_formal.py tlc --jar /tmp/tla2tools.jar` | 6.90s for the original three specs; the first JVM was cold and TLC timed that spec at 5s | 0.92s then 0.79s for all ten specs at once, on a warm machine |

`check` did not get a lower wall time. Process startup is most of the 0.06s,
and the extra machines fit into that same window. Under cProfile, `check_all`
went from 0.11s (three machines, every guard re-parsed) to 0.03s (ten
machines, formulas compiled once). A warm run of the old `ParallaXQuic` spec
alone was 0.57s; TLC's own timer reports 0 seconds of model checking once the
JVM is up. The 0.79s figure is not a cold-JVM number.

## Correspondence

`correspond` reads the Rust and checks the order the model depends on, including:

- client establish: session keys, then PQ rekey, then key exchange, then identity; `CONNECT` only after that returns
- server: early `reserve_pending` refusal returns the origin splice before authenticated establishment; a busy replay-cache lock refuses admission
- pending reservation checks capacity, freshness, committed replay, then unique pending transcript; valid PX1Q precedes the late commit, whose refusal returns before `apply_server_pq_rekey`
- the identity flight is written before the server data-mode read
- both directions of a rekey update together, and the epoch steps by one
- identity verification refuses a missing PQ binding
- QUIC client and server `process_message` arms, and the 0-RTT guard running only after the binder check
- 0-RTT `accept_ticket` failing closed when the lock is busy or the cache is checked out
- the client consuming the cached ticket, sending the probe, waiting for 1-RTT, and storing a new ticket only on `Verified`
- `stage_insert` order, and capacity 0 returning Inserted before anything is staged
- probe reply classification, and retain / hard-fail / stay
- client and server `write_handshake` key order
- close idempotence, at most one close packet, and drain before later timers
- BBR loss not assigning the mode, and ProbeRTT only after the pipe fills
- first-byte fixed bit, short header, and long type, including Retry
- PX1P status bytes 0, 1, and 2
- record batches reserve before dispatch, poison before returning a worker failure, and publish only after successful collection; fresh-key rekey preserves poison
- PX1F reassembly checks total/offset before append and resets the total latch and buffer before emitting a complete frame
- TCP MUX admission prunes completed tasks, rejects duplicates/capacity before spawn, keeps the supervisor on FIN and cancellation, and joins both relay directions
- the PX1I caller authenticates, checks capacity/total/offset, then appends and returns only a whole payload; one outer establishment deadline includes reading and verification

A reorder that removes one of those anchors fails `correspond` even though the TLA+ model itself still checks.

## Bounded record batches (`ParallaXRecords`)

The added record model follows `RecordSequence` and
`DataRecordCodec::seal_records_into_parallel`: a batch consumes its complete
sequence range before workers run; a worker failure permanently poisons the
codec; ciphertext is published after all workers succeed. It explores batches
of one or two records in a three-sequence window, across two key epochs.
`FreshKeyRekey` assumes a new independent key/nonce namespace. The actual u64
arithmetic and AES-GCM key-usage limit remain separate Kani properties.
An independent per-epoch reservation history survives rekey and detects rollback
even if all mutable counter copies are restored together. The positive
`FreshKeyCanReuseSequence` witness permits sequence reuse only under a fresh key.
This model does not prove AEAD security, worker scheduling, serial opening,
or the freshness of derived key bytes.

| Invariant | Unreachable situation |
| --- | --- |
| `ReservedRangesNeverOverlap` | A new batch starts inside an earlier reservation in the same key epoch |
| `ReservationIsNeverRolledBack` | Failure restores a consumed sequence range |
| `FailedBatchPoisonsPermanently` | A worker failure loses its poison, including through rekey |
| `PoisonedCannotDispatch` | A poisoned codec reserves or publishes another batch |
| `PublishOnlyWholeSuccess` | A partial or failed batch publishes ciphertext |
| `RecordWindowIsBounded` | The model leaves its three-sequence, two-epoch bounds |

## Bounded framed commands (`ParallaXFragments`)

The PX1F model follows `FramedReassembler::push` and enumerates every positive
chunk partition of total lengths 1, 2, and 3, followed by a second frame through
the same reassembler. Decode errors, excess capacity, changed totals, and wrong
offsets are abstract reject classes: their concrete byte parser is covered by
Rust tests, not enumerated by this model. The model assumes that the caller
aborts on a rejected chunk; it does not claim that `push` itself becomes
permanently poisoned. PX1I shares the offset-chunk wire decoder but has separate
caller reassembly, which this model does not prove.

| Invariant | Unreachable situation |
| --- | --- |
| `FragmentsStayWithinTotal` | Partial accumulation exceeds its latched total |
| `EmitOnlyCompleteFrame` | A partial frame is returned as a complete payload |
| `CompletionClearsLatch` | A completed frame leaves its old total or buffer for the next frame |
| `RejectedChunkEmitsNothing` | A rejected call returns a frame |
| `PartialChunkEmitsNothing` | A partial call returns a frame |
| `FrameCountIsBounded` | The model exceeds two completed frames |

These two models are checked by both the Python explorer and the generated
TLA+/TLC specs through the existing `formal` workflow. Counterexample self-tests
exercise nonce rollback, poison removal, early emission, and stale completion
state. They check the checker and its contracts; they are not attacks on a
running proxy or a whole-implementation proof.

## TCP MUX lifecycle (`ParallaXMux`)

This model follows `process_server_mux_frame`, `ServerMuxStreams`, and
`server_mux_upstream_task`. It has two stream IDs and explores capacity one
and two. Each stream records its supervisor phase (`none`, `connecting`,
`relaying`, `cancelling`), upload routing, both relay halves, and its charged
slot. Pre-step snapshots check that each local event preserves its sibling.
The event-parity bit permits repeated ignored DATA/FIN/RESET and Cover frames;
there is no trace-length cutoff, so all reachable cycles are explored.

OPEN creates a connecting supervisor only after duplicate and capacity checks.
New DATA is enqueued only while upload routing exists. FIN removes that routing;
queued upload completion and target EOF occur independently. Both halves must
finish before natural slot release. RESET or a stalled/failed target requests
cancellation, and the slot stays charged until a separate task-exit action.
Resolution, connect, socket tuning, and initial-write failures affect only that
stream while the shared carrier is healthy. A stream idle-watchdog exit also
releases that stream's halves and slot. Cover leaves both streams intact.
Carrier teardown enters a closing phase, requests aborts, and reaches closed
only after all supervisors exit; it does not assume immediate abort completion.
Task completion and the next admission's `prune_finished` are combined into
one admission-visible transition, rather than modeling stale map entries.

| Invariant | Unreachable situation |
| --- | --- |
| `MuxCapacityCountsBothHalves` | Two unfinished supervisors occupy a one-slot carrier |
| `MuxLocalEventsPreserveSibling` | A stream-local event changes another stream's phase, route, halves, or slot |
| `MuxRejectedOpenAndCoverAreInert` | Rejected OPEN or Cover changes either stream |
| `MuxTeardownReleasesAllSlots` | Completed carrier teardown leaves an owned slot or target half |
| `MuxOwnership0`, `MuxOwnership1` | Supervisor ownership and slot accounting disagree |
| `MuxLiveHalfKeepsSlot0`, `MuxLiveHalfKeepsSlot1` | Either live relay half has an uncharged slot |
| `MuxFinIsHalfClose0`, `MuxFinIsHalfClose1` | FIN prematurely destroys a supervisor or target half |
| `MuxDataRequiresUploadRoute0`, `MuxDataRequiresUploadRoute1` | New DATA is enqueued after upload FIN/RESET |
| `MuxResetKeepsSlotUntilExit0`, `MuxResetKeepsSlotUntilExit1` | An abort request releases its slot before task exit |

This proves safety of the stated finite abstraction. It does not prove eventual
task cancellation, OS fd closure, byte/queue ordering, scheduler fairness,
arbitrary stream counts, client download dispatch, or the native QUIC-bidi
lifecycle. A shared downlink/control-queue failure may end the whole carrier;
that failure is represented by `CarrierTeardown`, rather than by a stream-local
isolation claim. Source anchors detect selected changes in production control order;
they are not a semantic equivalence proof between Rust and the model.

## PX1I caller (`ParallaXIdentityChunks`)

Unlike the PX1F helper, `read_server_identity_payload` performs its own PX1I
accumulation. This model enumerates external metadata with total 0..4, offset
0..3, and chunk length 0..4: all 100 candidate combinations, including invalid
ones, are selected before validation. The capacity is scaled to three bytes.
Each candidate then passes through AEAD outcome, structural metadata checks,
capacity, latched total, offset continuity, append, and completeness. An append
snapshot retains the previous cursor, so a gap/overlap bypass violates an
assertion rather than disappearing inside a valid-input assumption.

A complete payload still requires the PQ binding and successful identity
verification before CONNECT. EOF, I/O, AEAD, inconsistent metadata, missing
binding, and signature/identity-payload failure all terminate establishment.
The outer absolute establishment deadline can interrupt any pre-CONNECT
stage, including partial accumulation and the verification await.

| Invariant | Unreachable situation |
| --- | --- |
| `IdentityBufferNeverExceedsCap` | Accepted metadata grows the caller buffer past the bounded capacity |
| `IdentityAppendRequiresValidatedMetadata` | Append accepts mismatched total, a gap/overlap, or an out-of-range end |
| `IdentityPartialCannotVerify` | Partial accumulation reaches the assembled, verified, or CONNECT phase |
| `IdentityVerificationNeedsWholeBoundPayload` | Identity succeeds without a complete payload or PQ binding |
| `IdentityFailureBlocksConnect` | An establishment failure sends CONNECT |
| `IdentityConnectWaitsForVerification` | CONNECT bypasses complete accumulation or identity verification |

AEAD and signature outcomes are opaque pass/fail events, not proofs of the
cryptographic primitives. Arbitrary byte strings, u32-size inputs, allocator
behavior, partial TCP-record parser internals, and clock/scheduler behavior are
outside this bounded model. EOF/deadline are events; no real-time termination
bound is proved. Existing Rust tests and the full-session model cover adjacent
layers independently.

Additional counterexample self-tests remove capacity/offset checks, free slots
on FIN/abort, cancel a sibling, deliver DATA after FIN, emit partial identity,
and bypass failed identity/deadline gates. These checks must fail with a named
invariant; source-contract tests separately remove the real task-retention and
PX1I offset anchors from temporary source copies.
