# Protocol state machines

Exhaustive check of the control-state machines that are easy to get wrong:
the TCP session (handshake, PQ rekey, replay, identity, reconnect), the QUIC
TLS handshake order, 0-RTT ticket use, the replay-insert decision, the UDP
probe outcome, the inbound auth gates, QUIC key installation, QUIC close and
drain, the BBR mode graph, and the QUIC first-byte class.

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
origin and install no keys. A degenerate all-zero X25519 shared secret is
rejected after that auth, inside `derive_keys_from_shared`, and closes
without splicing. The same reject in `hybrid_sandwich_rekey` fails the PQ
rekey after that insert and does not advance the epoch. Replay is decided
when the PQ rekey frame is committed. A missing cache fails closed the same way. `FallbackReason::Replay`
is not constructed; a replay, a stale timestamp, or a full cache closes the
connection before `apply_server_pq_rekey`.

| Invariant | Unreachable situation |
| --- | --- |
| `AppOnlyAfterIdentity` | Application data before identity, or at any epoch other than 1, or with dead keys |
| `VerifiedImpliesBinding` | `verified` / `app` without a PQ identity binding and live epoch-1 keys |
| `RekeyedImpliesFreshCommit` | A rekeyed session whose replay cache insert was not fresh |
| `ReplayClosesBeforeRekey` | Replay, stale, or cache-full promoting the session past epoch 0 |
| `IdleAndReconnectAreFresh` | A reconnect that keeps the previous epoch, binding, keys, UDP leg, or failure class |
| `AuthedHasNoKeys` | Authentication that has already installed epoch-0 keys |
| `PostAuthDegenerateDoesNotSplice` | An all-zero shared secret after auth that splices or installs keys |
| `RekeyDegenerateStaysAtEpochZero` | An all-zero rekey ephemeral that advances the epoch or splices |
| `SpliceIsTheInboundReject` | A fallback splice after keys exist |
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
are decided under a free lock and do not burn the ticket. The journal fsync
is deferred; a restart before it can accept the ticket again.
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
| `DurableAcceptStaysBurned` | A durable journal whose accept was cleared |
| `RestartUndoesUndurableAccept` | A pre-fsync restart that leaves the ticket burned |
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
function. The constant-time DH ballast is not a state.

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
- server: replay commit returns before `apply_server_pq_rekey`; the identity flight is written before the data-mode read
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

A reorder that removes one of those anchors fails `correspond` even though the TLA+ model itself still checks.
