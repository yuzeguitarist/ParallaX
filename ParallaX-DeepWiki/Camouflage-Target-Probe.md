# Camouflage Target Probe
Relevant source files

- [src/cli.rs](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/cli.rs)
- [src/probe.rs](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/probe.rs)

The `plx probe` utility is a diagnostic tool designed to evaluate the suitability of a remote domain for use as a ParallaX camouflage target. Because ParallaX mimics legitimate TLS traffic to bypass censorship, the target domain (fallback destination) must support modern protocol features like TLS 1.3 and ALPN `h2` to ensure the camouflage is indistinguishable from standard browser behavior.

### Purpose and Scope

The probe performs a real-world TLS handshake with a candidate domain to measure latency and verify protocol support. It specifically looks for:

1. TCP Reachability: Basic connectivity to the target port.
2. TLS 1.3 Support: Mandatory for ParallaX's camouflage model.
3. ALPN Negotiation: Verification of HTTP/2 (`h2`) support.
4. Post-Handshake Behavior: Detection of session tickets or post-handshake records, which affect how the ParallaX client handles the "drain" phase of a connection.

---

### Data Structures and Models

The probing logic is centered around several key structures defined in `src/probe.rs`.

| Structure | Role |
| --- | --- |
| `ProbeTarget` | Represents the destination to be tested, containing a host and a port [src/probe.rs#45-48](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/probe.rs#L45-L48) |
| `ProbeReport` | The final result containing latencies, protocol flags, scores, and a verdict [src/probe.rs#58-69](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/probe.rs#L58-L69) |
| `ProbeVerdict` | An enum representing the suitability level: `Good` (Recommended), `Usable`, or `Bad`[src/probe.rs#51-55](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/probe.rs#L51-L55) |
| `ProbeSignals` | Internal structure used to collect raw metrics during the handshake [src/probe.rs#252-259](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/probe.rs#L252-L259) |

#### Target Resolution

The `target_from_config` helper function allows the probe to automatically extract the camouflage target from an existing `parallax.toml`. If the config is in `Server` mode, it uses the `fallback_addr`; if in `Client` mode, it uses the configured `sni`[src/probe.rs#168-192](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/probe.rs#L168-L192)

### Probing Logic Flow

The probe follows a sequential execution path from TCP connection to TLS handshake completion.

#### 1. Implementation Flow Diagram

This diagram maps the natural language steps to the internal function calls and structures.

[Flowchart Diagram]

Sources:[src/cli.rs#189-203](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/cli.rs#L189-L203)[src/probe.rs#168-230](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/probe.rs#L168-L230)[src/probe.rs#307-330](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/probe.rs#L307-L330)

#### 2. TLS Handshake and Verification

The probe uses `rustls` to perform the handshake. A specialized `ProbeServerCertVerifier` is used to allow the handshake to complete even if the certificate is self-signed or invalid, as the goal is to test protocol capability rather than trust [src/probe.rs#434-460](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/probe.rs#L434-L460)

The `complete_tls_probe` function drives the state machine:

1. Initialization: Configures a `rustls::ClientConfig` with TLS 1.3 only and ALPN `h2`, `http/1.1`[src/probe.rs#307-320](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/probe.rs#L307-L320)
2. Handshake: Measures the time from the first `write_tls` (ClientHello) to the completion of the handshake [src/probe.rs#335-360](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/probe.rs#L335-L360)
3. Post-Handshake Drain: After the handshake, the probe waits briefly (220ms) to see if the server sends session tickets or other records. This is crucial for ParallaX to avoid "trailing data" detection [src/probe.rs#27-28](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/probe.rs#L27-L28)[src/probe.rs#400-432](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/probe.rs#L400-L432)

### Scoring Algorithm

The `calculate_score` function converts raw signals into a 0-100 score [src/probe.rs#462-498](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/probe.rs#L462-L498)

| Criteria | Weight / Logic |
| --- | --- |
| TLS 1.3 | Mandatory. If missing, score is capped at 20 [src/probe.rs#469-472](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/probe.rs#L469-L472) |
| TCP Latency | -10 points if > 200ms; -20 points if > 500ms [src/probe.rs#475-480](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/probe.rs#L475-L480) |
| ALPN h2 | +20 points for supporting HTTP/2 [src/probe.rs#482-484](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/probe.rs#L482-L484) |
| Post-Handshake | +10 points if session tickets are observed (indicates a standard CDN/Web server) [src/probe.rs#486-488](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/probe.rs#L486-L488) |

Verdict Mapping:

- Good: Score >= 80.
- Usable: Score >= 50.
- Bad: Score < 50.

### Code Entity Association

The following diagram associates the system concepts with specific code entities and their locations.

[Class Diagram]

Sources:[src/cli.rs#189-203](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/cli.rs#L189-L203)[src/probe.rs#45-70](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/probe.rs#L45-L70)[src/probe.rs#307-432](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/probe.rs#L307-L432)[src/probe.rs#434-460](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/probe.rs#L434-L460)[src/probe.rs#462-498](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/probe.rs#L462-L498)

### Key Functions Reference

#### `probe(target: ProbeTarget, sni: String)`

The primary entry point. It wraps `probe_with_timeout` using a default 5-second deadline [src/probe.rs#194-196](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/probe.rs#L194-L196)

#### `read_record(reader)`

Used during the post-handshake drain phase to parse raw TLS records from the stream. It validates the record type and length to ensure the server is behaving according to the TLS specification [src/tls/record.rs#12-40](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/tls/record.rs#L12-L40)

#### `ProbeReport::summary()`

Formats the results into a human-readable string, including PASS/FAIL status for each phase and a list of "notes" explaining the verdict [src/probe.rs#119-165](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/probe.rs#L119-L165)

Sources:

- `src/cli.rs`: Command parsing and high-level execution.
- `src/probe.rs`: Core probing logic, scoring, and certificate verification.
- `src/tls/record.rs`: TLS record layer parsing for the drain phase.