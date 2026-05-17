# Getting Started & CLI Reference
Relevant source files

- [src/bin/plx.rs](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/bin/plx.rs)
- [src/cli.rs](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/cli.rs)
- [src/config.rs](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/config.rs)
- [src/main.rs](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/main.rs)

The `plx` command-line interface is the primary entry point for interacting with the ParallaX proxy system. It provides utilities for environment initialization, cryptographic key generation, camouflage target evaluation, and running the core proxy runtimes.

## Installation and Quick Start

ParallaX is built using Rust and requires the `tokio` runtime [src/main.rs#1-4](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/main.rs#L1-L4) The CLI entry point is defined in `src/cli.rs`.

### Basic Workflow

1. Initialize: Find a suitable camouflage target (e.g., a website with TLS 1.3 support) and generate a configuration.
2. Keygen: Generate X25519 and Post-Quantum keys for secure communication.
3. Deploy: Transfer the server configuration to a VPS and start the server.
4. Connect: Start the local client to establish a SOCKS5 proxy.

Sources: [src/cli.rs#111-203](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/cli.rs#L111-L203)[src/main.rs#1-4](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/main.rs#L1-L4)

---

## CLI Command Reference

The `plx` tool uses a subcommand-based interface [src/cli.rs#36-109](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/cli.rs#L36-L109)

### `plx init`

Automates the creation of `parallax.client.toml` and `parallax.server.toml`. It performs a probe of the destination domain to ensure it is a viable camouflage target [src/cli.rs#96-108](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/cli.rs#L96-L108)

- Usage: `plx init <DOMAIN> --server-addr <VPS_IP:PORT>`
- Effect: Generates fresh X25519, ML-KEM, and ML-DSA keys and populates templates with the probed SNI and fallback settings.

### `plx probe`

Evaluates a domain's suitability as a camouflage target [src/cli.rs#89-94](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/cli.rs#L89-L94)

- Logic: It checks for TLS 1.3 support, ALPN (h2/http1.1), and measures latency.
- Output: A `ProbeReport` with a `ProbeVerdict` (Good, Usable, or Bad).

### `plx keygen`

Generates a standalone X25519 key pair [src/cli.rs#43-44](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/cli.rs#L43-L44)

- Output: Base64-encoded private and public keys [src/cli.rs#127-131](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/cli.rs#L127-L131)

### `plx serve` & `plx client`

Runs the ParallaX runtime in either server or client mode [src/cli.rs#48-62](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/cli.rs#L48-L62)

- `--quic`: Optional flag to use the UDP/QUIC transport instead of the default TCP camouflage transport [src/cli.rs#52-60](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/cli.rs#L52-L60)
- Config: Defaults to loading `parallax.toml` in the current directory [src/cli.rs#40](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/cli.rs#L40-L40)

### `plx check`

Validates a configuration file without starting the runtime [src/cli.rs#39-42](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/cli.rs#L39-L42) It verifies:

- Base64 encoding of keys [src/config.rs#161-166](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/config.rs#L161-L166)
- Socket address formats [src/config.rs#159-173](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/config.rs#L159-L173)
- Traffic padding constraints [src/config.rs#192-197](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/config.rs#L192-L197)

### `plx bench`

Runs local CPU-only benchmarks for performance evaluation [src/cli.rs#65-74](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/cli.rs#L65-L74)

- Metrics: Measures throughput and latency for `DataRecordCodec` (seal/open) and Post-Quantum (ML-KEM) operations [src/cli.rs#162-175](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/cli.rs#L162-L175)

Sources: [src/cli.rs#36-109](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/cli.rs#L36-L109)[src/cli.rs#116-203](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/cli.rs#L116-L203)[src/config.rs#152-187](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/config.rs#L152-L187)

---

## Configuration File Format

ParallaX uses TOML for configuration. The file is structured into global settings (`mode`, `crypto`, `traffic`) and mode-specific sections (`client`, `server`) [src/config.rs#51-59](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/config.rs#L51-L59)

### Core Structure

| Section | Field | Description |
| --- | --- | --- |
| `[crypto]` | `psk` | Base64 pre-shared key (min 32 bytes) [src/config.rs#78-81](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/config.rs#L78-L81) |
| `[traffic]` | `min_padding` | Minimum bytes added to every data record [src/config.rs#115](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/config.rs#L115-L115) |
| `[traffic]` | `max_delay_ms` | Maximum jitter delay for packet transmission [src/config.rs#121](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/config.rs#L121-L121) |
| `[client]` | `server_addr` | The IP/Port of your ParallaX server [src/config.rs#86](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/config.rs#L86-L86) |
| `[server]` | `fallback_addr` | Where to redirect unauthenticated probes [src/config.rs#98](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/config.rs#L98-L98) |

### Configuration Validation Logic

The `Config::validate` function ensures that the system does not start with insecure or impossible parameters.

Title: Configuration Validation Data Flow

[Flowchart Diagram]

Sources: [src/config.rs#51-128](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/config.rs#L51-L128)[src/config.rs#152-205](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/config.rs#L152-L205)

---

## CLI Execution Flow

When a user runs `plx`, the `cli::run()` function initializes logging and dispatches the command to the appropriate module.

Title: CLI Command Dispatch to Code Entities

[Flowchart Diagram]

Sources: [src/cli.rs#111-203](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/cli.rs#L111-L203)[src/bin/plx.rs#1-4](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/bin/plx.rs#L1-L4)[src/config.rs#63-66](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/config.rs#L63-L66)

### Key Code Entities

- `Cli` Struct: Defines the `clap` interface [src/cli.rs#25-34](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/cli.rs#L25-L34)
- `Config` Struct: The central data structure for all settings [src/config.rs#52-59](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/config.rs#L52-L59)
- `server::run`: The entry point for the TCP-based server runtime [src/cli.rs#150](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/cli.rs#L150-L150)
- `runtime::run`: The entry point for the TCP-based client runtime [src/cli.rs#159](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/cli.rs#L159-L159)
- `quic_runtime`: Handles UDP-based transport when the `--quic` flag is used [src/cli.rs#148-157](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/cli.rs#L148-L157)

Sources: [src/cli.rs#25-109](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/cli.rs#L25-L109)[src/config.rs#51-128](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/config.rs#L51-L128)