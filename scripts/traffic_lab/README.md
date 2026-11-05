# Traffic corpus evaluation

This analyzer treats each complete capture/trial as one observation. It does
not split windows from a single connection across training and test data, and
does not certify that traffic is indistinguishable.

Run integrity tests with:

```sh
python3 -B -m unittest discover -s scripts/traffic_lab -p 'test_*.py' -v
python3 -B -m unittest discover -s ops/traffic-lab -p 'test_*.py' -v
```

Node.js is required for the helper's emitted browser-JavaScript tests. Those
tests skip locally when Node.js is absent; CI requires it before running them.

Run the corpus evaluation with:

```sh
python3 -B scripts/traffic_lab/analyze.py analyze corpus.json --output report.json
```

Reports have status `evaluated` or `insufficient_evidence`, never a security
PASS. Exit status 2 means insufficient evidence or invalid input. Output files
are created exclusively so a previous evidence artifact is not overwritten.
The default target false-positive rate is 1%; `--target-fpr` changes the stated
target. Thousands of normal independent groups may be needed to support a much
lower target. A chance AUC from these models cannot exclude stronger detectors.

The default models are a dependency-free standardized linear centroid and
optional scikit-learn logistic regression and random forest. Missing optional
backends are reported as insufficient evidence. Backend versions, analyzer and
manifest SHA-256, feature names, and seed are recorded. All standardization and
model fitting use training data only. Thresholds use normal calibration data;
the final test groups are not used for threshold selection.

## Corpus manifest

```json
{
  "schema": "parallax-traffic-corpus-v1",
  "purpose": "protocol_comparison",
  "captures": [
    {
      "capture_id": "opaque-trial-001-a",
      "label": "browser",
      "implementation": "Safari direct through plain SOCKS",
      "path": "captures/opaque-trial-001-a.pcap",
      "format": "pcap",
      "sha256": "ARTIFACT_SHA256",
      "server_port": 58444,
      "capture_group": "paired-trial-001",
      "workload": "single-fetch-small",
      "site": "site-01",
      "day": "2026-11-04",
      "network": "network-01",
      "vantage": "mini-loopback-pcap"
    }
  ]
}
```

Each capture group must contain both classes with matching workload, site, day,
network, and capture vantage. Include a corresponding `parallax` capture in the
same group. Artifacts are checked against their hashes; duplicate artifacts
cannot count as independent captures. Supported formats are `pcap`, the E2E
capture's `record_tsv`, and the existing Safari fixture's `safari_tsv`.
Capture paths must resolve inside the manifest's directory, including symlink
targets. Put the manifest at the root of the intended corpus.

For browser/browser negative controls set `purpose` to `negative_control`, use
`class_label: "A"` and `class_label: "B"` instead of `label`, and truthfully
record the same actual `implementation` for both classes. Do not relabel a real
browser as an actual ParallaX implementation. Positive-control corpora can use
`purpose: "positive_control"`. Synthetic machinery controls in the analyzer
supplement actual independent control captures.

No filename, IP, port, implementation string, capture ID, site, day, or workload
is used as a model feature. Those fields only select artifacts, check matching,
record provenance, or define holdout groups. Features are observable record
sizes, counts, direction runs and inter-arrival times.

## Holdouts and uncertainty

By default, separate evaluations hold out entire capture groups, sites,
workloads, days and networks. Each axis deterministically orders its groups,
then cuts at `max(2, floor(3*n/5))` and `max(3, floor(4*n/5))` for the
train/calibration/test split. This approximates 60/20/20; six groups split as
3/1/2. At least six groups and two captures per class in every partition are
required; more observations are needed for useful uncertainty.
Use repeated `--holdout` arguments for a deliberately narrower evaluation and
retain that limitation in any claim. A single-day corpus cannot establish
cross-day generalization.

Reports include held-out AUC, a group-bootstrap AUC interval, test TPR/FPR with
Clopper-Pearson binomial intervals, and a conservative interval for the event
that any normal capture in a held-out group is flagged. The latter prevents
many correlated captures from one site/day from manufacturing low-FPR support.
Binomial intervals still assume independence between groups. Bootstrap
intervals condition on the fitted model and observed groups.

Paired-group label permutations refit the model on the unchanged held-out
partition structure. They are exploratory diagnostics, with finite resolution
and multiple comparisons across models/axes; they do not prove equivalence.

## Packet capture scope

The local browser helper in `ops/traffic-lab/relay.py` runs controlled fetch
workloads, not complete rendered website sessions. For speed.cloudflare.com,
`download` verifies 1MiB, `page_download` verifies sequential 8KiB and 1MiB
responses, and the single/browse/interactive/idle/burst profiles verify 8KiB
per request. These use the CORS-enabled download endpoint, not the site's HTML
homepage. Each request has a unique trial/request URL. Upload reports a 2xx
response but does not claim a server-attested uploaded byte count. Other hosts
can produce opaque fetch responses; they are never counted as verified bodies.
`bootstrap_download` performs POST1536, GET8192, POST1536, GET4096 and GET1MiB,
sequentially with no extra pause. It is a synthetic bootstrap counterexample
constructed from a discovery rule, not a rendered app or independent holdout.
POST response bytes are counted truthfully and do not attest uploaded size.
Use `--origin-ip` to match the baseline observer to the proxy's pinned CDN edge;
it must belong to the hostname's current DNS allowlist. This remains a plain
byte relay, with the browser's SNI and certificate validation intact. The option
does not change the upstream SOCKS proxy's destination policy.

PCAP import requires `tshark`. It keeps per-flow TCP sequence spaces, verifies
captured SYNs, checks conflicting retransmissions, reassembles out-of-order
segments, and rejects gaps, incomplete TLS records, missing TCP close, and
allocation/record-count overruns. Keep capture running through both FINs when
shutting down the trial's relays. Each FIN sequence must match its direction's
complete reassembled payload end. Reset-terminated captures are rejected because
a reset does not establish complete payload coverage. Multiple flows from one browser workload remain a single capture-level
observation; flow IDs are retained only as provenance. Packet times, passive
reassembly completion times, and userspace forwarding times are different
vantages. Compare matched capture vantages and workloads.

The browser helper records `resource_protocols` from Resource Timing for each
completed trial URL. `unavailable` is missing browser evidence, not a guessed
protocol. This reports the fetched resource's protocol; a system relay can use
a different outer transport. Confirm the actual packet path and Initial before
calling a capture a direct HTTP/3 baseline. On macOS, PKTAP can raise a requested
short snaplen to its full minimum: inspect the capture log, retain process scope,
and exclude dropped or partial captures from quantitative comparisons.

Equal-time records retain TCP byte order within a direction and the packet
observation order in which reassembly completed. They are not sorted by record
size or direction. These are passive completion times, not endpoint write times.

The `compare` command emits only exploratory record-length distances for two
unmatched captures. It always reports insufficient evidence, including when
large differences appear. It does not estimate a deployed detector's success.

## Matched additional byte-stream delay

`ops/traffic-lab/shaper.py` is an independent loopback-only shim. It forwards
TCP bytes unchanged to a fixed loopback port, adding the same fixed delay to
each direction. A chunk's due time is its userspace read time plus the delay;
independent reader/writer tasks allow chunks to wait concurrently instead of
adding another full delay per chunk. It does not parse TLS or CONNECT targets.
Failure diagnostics use a bounded, best-effort queue. If stdout stalls, new
diagnostic events can be dropped so forwarding and shutdown do not wait for
the log consumer.

```sh
python3 -B ops/traffic-lab/shaper.py \
  --listen-port 58454 --upstream-port 58444 --delay-ms 50
```

For a normal trial, use the existing whitelist gate with
`relay.py --normal-next-hop-port 58454` (plus its usual host/output options):
gate1082 → shim58454 → observer58444 → DNS-allowlisted, optionally pinned origin.
For the proxy trial, use the same shim with `--upstream-port 58453`, gate →
SOCKS1080 → task client configured with `server_addr = "127.0.0.1:58454"` → shim
→ server58453. The relay's `--upstream-socks-port` and `--normal-next-hop-port`
are mutually exclusive. Its actual listener ports must differ, and an explicit
backend cannot point to any of those listeners. The PAC-only proxy port is a
reference, not another bound listener. These checks reject direct self-loops;
they do not prove absence of loops across separate processes.

Run the two arms sequentially through the same shim program, capture its front
port58454, and retain the ready log's PID, UTC time and exact parameters. Each
direction has eight queued chunks of at most 16 KiB (128 KiB queue capacity), plus
at most one producer and one consumer chunk (160 KiB application chunk data).
These bounds exclude asyncio stream/transport and OS socket buffers. Delay is
finite 0..60000 ms; connect has a 5 s bound and stalled reads, queue waits and drains
have a 90 s bound. EOF drains the queued bytes before forwarding a half-close;
the reverse direction can still reply. SIGTERM cancels active handlers and
closes owned sockets within bounded cleanup. Stopping mid-transfer censors the
trial; do not treat discarded queued bytes as a completed capture.

For example, 50 ms or 150 ms per direction means matched **additional byte delay**,
not equal overall RTT or a real TCP path/loss simulator. Public-origin delay
remains. SYN/ACK timing, congestion windows, retransmission and packet loss are
not controlled by this model. No production delay setting, route, PF rule or
system proxy is changed by either helper.

## Independent blind challenge

```sh
python3 -B scripts/traffic_lab/analyze.py blind-export corpus.json \
  --output challenge/samples.json --oracle-output withheld/oracle.json
```

Create the two output directories first. Give an independent analyst only
`challenge/samples.json`. It contains shuffled opaque sample IDs, fixed capture
features, record direction/length/timing sequences, and per-flow sequences. PCAP
samples additionally include public ClientHello structural vectors: cipher and
extension order/lengths, groups, signatures, versions, ALPN and key-share sizes.
GREASE IDs are normalized; random bytes, session IDs, key material and SNI values
are omitted. There are no labels, filenames, addresses, ports, implementation
names, sites or dates in the challenge. Observable fingerprint differences are
retained rather than normalized into the same profile.

New exports use `traffic-blind-challenge-v2`. PCAP flows also include every
captured TCP packet as `[t, direction, TCP_payload_bytes, SYN, FIN, RST]`,
including zero-payload packets. Packet and TLS-record times share the first
TLS record's origin, so SYN times may be negative. Other TCP flags, windows,
sequence numbers and payload contents are not exported. TSV inputs explicitly
report packet observations as unavailable. Packet observations are bounded both
per capture and across a public challenge; an oversized challenge must be split.
The automated models' feature vectors remain TLS-derived; packet observations
are available to independent analysts, not silently added as model features.

Keep TCP EOF timing visible when comparing a late encrypted control record with
an ordinary connection close. TLS-record-only views can hide the ordinary FIN
at the corresponding time. A captured FIN may also reflect controlled process
teardown rather than natural session expiry; do not treat flow duration alone
as an implementation property. Previously frozen v1 challenges stay immutable.

Keep `withheld/oracle.json` separate. It contains truthful class/provenance
mapping, the private shuffle seed, and a hash binding it to the exact public
artifact. The oracle is created with mode 0600. Random ordering is reproducible
from the withheld seed, which is not given to the analyst. The challenge remains
a pilot when the corpus is small, unmatched, or lacks independent holdouts.
