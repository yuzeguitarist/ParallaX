# Configuration Reference
Relevant source files

- [src/cli.rs](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/cli.rs)
- [src/config.rs](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/config.rs)

The `parallax.toml` file is the central authority for configuring the ParallaX runtime. It defines the operational mode (Client vs. Server), cryptographic identity material, traffic shaping parameters, and network routing rules. The configuration is parsed using `serde` and validated against security and protocol constraints before the runtime initializes.

## Core Configuration Structure

The configuration is represented by the `Config` struct [src/config.rs#52-59](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/config.rs#L52-L59) which aggregates several sub-sections.

### Mode Selection

The `mode` field [src/config.rs#53](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/config.rs#L53-L53) determines which runtime logic is executed.

- `client`: Runs the SOCKS5 proxy and initiates camouflage TLS connections [src/cli.rs#153-161](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/cli.rs#L153-L161)
- `server`: Runs the authenticated TLS listener and handles fallback traffic [src/cli.rs#144-152](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/cli.rs#L144-L152)

### CryptoConfig (PSK)

The `crypto` section [src/config.rs#78-81](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/config.rs#L78-L81) defines the Pre-Shared Key (PSK) used for the initial authentication of the TLS ClientHello.

| Field | Type | Requirement | Description |
| --- | --- | --- | --- |
| `psk` | String | Base64, $\ge$ 32 bytes | Used to derive `client_auth_key` and `server_auth_key` for session ID tagging [src/config.rs#153](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/config.rs#L153-L153) |

### TrafficConfig (Obfuscation)

The `traffic` section [src/config.rs#113-128](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/config.rs#L113-L128) controls the statistical properties of the data stream to resist traffic analysis.

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `min_padding` | `u16` | 0 | Minimum bytes added to each `DataRecord`[src/config.rs#115](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/config.rs#L115-L115) |
| `max_padding` | `u16` | 512 | Maximum bytes added to each `DataRecord`[src/config.rs#117](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/config.rs#L117-L117) |
| `min_delay_ms` | `u16` | 0 | Minimum artificial delay before sending a record [src/config.rs#119](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/config.rs#L119-L119) |
| `max_delay_ms` | `u16` | 10 | Maximum artificial delay before sending a record [src/config.rs#121](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/config.rs#L121-L121) |
| `cover_min_interval_ms` | `u16` | 5000 | Minimum interval between cover (dummy) packets [src/config.rs#123](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/config.rs#L123-L123) |
| `cover_max_interval_ms` | `u16` | 15000 | Maximum interval between cover (dummy) packets [src/config.rs#125](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/config.rs#L125-L125) |
| `max_concurrent_streams` | `u8` | 1 | Currently restricted to 1 for fingerprint safety [src/config.rs#127](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/config.rs#L127-L127) |

Sources:[src/config.rs#52-142](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/config.rs#L52-L142)[src/cli.rs#116-161](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/cli.rs#L116-L161)

---

## Client Configuration

The `[client]` section [src/config.rs#84-93](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/config.rs#L84-L93) is mandatory when `mode = "client"`. It defines the upstream ParallaX server and the camouflage profile to use.

### Fields Reference

- `listen`: The local `SocketAddr` for the SOCKS5 proxy (e.g., `127.0.0.1:1080`) [src/config.rs#85](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/config.rs#L85-L85)
- `server_addr`: The remote ParallaX server address [src/config.rs#86](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/config.rs#L86-L86)
- `sni`: The Server Name Indication to use in the camouflage ClientHello [src/config.rs#87](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/config.rs#L87-L87)
- `server_public_key`: Base64-encoded X25519 public key of the server [src/config.rs#88](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/config.rs#L88-L88)
- `server_pq_public_key`: Base64-encoded ML-KEM-1024 public key [src/config.rs#89](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/config.rs#L89-L89)
- `server_identity_public_key`: Base64-encoded ML-DSA-87 public key [src/config.rs#90](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/config.rs#L90-L90)
- `tls_profile`: The browser fingerprint to emulate (e.g., `Chrome124`, `Safari17`) [src/config.rs#92](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/config.rs#L92-L92)

### Configuration Logic Flow

The following diagram illustrates how the `Config` struct is used to initialize the `ClientHelloBuilder`.

Diagram: Client Configuration to Code Entity Mapping

Sources:[src/config.rs#84-93](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/config.rs#L84-L93)[src/tls/client_hello_builder.rs#12-45](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/tls/client_hello_builder.rs#L12-L45)[src/crypto/session.rs#18-22](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/crypto/session.rs#L18-L22)

---

## Server Configuration

The `[server]` section [src/config.rs#96-110](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/config.rs#L96-L110) is mandatory when `mode = "server"`. It defines how to handle inbound connections and where to proxy unauthorized traffic.

### Fields Reference

- `listen`: The `SocketAddr` to bind the server to (typically `0.0.0.0:443`) [src/config.rs#97](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/config.rs#L97-L97)
- `fallback_addr`: The upstream legitimate TLS server (e.g., `127.0.0.1:8443`) for unauthenticated probes [src/config.rs#98](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/config.rs#L98-L98)
- `data_target`: Optional static target for authenticated traffic. If `None`, uses the target requested by the client [src/config.rs#100](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/config.rs#L100-L100)
- `private_key`: Base64-encoded X25519 private key [src/config.rs#101](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/config.rs#L101-L101)
- `pq_secret_key`: Base64-encoded ML-KEM-1024 secret key [src/config.rs#102](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/config.rs#L102-L102)
- `identity_secret_key`: Base64-encoded ML-DSA-87 secret key [src/config.rs#103](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/config.rs#L103-L103)
- `authorized_sni`: A list of SNI strings that the server is allowed to impersonate [src/config.rs#107](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/config.rs#L107-L107)
- `replay_cache_path`: Path to the disk-backed replay protection database [src/config.rs#105](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/config.rs#L105-L105)

### Inbound Decision Logic

The server uses the `authorized_sni` and `private_key` to determine if an inbound TLS ClientHello is a ParallaX request or should be sent to the `fallback_addr`.

Diagram: Server Inbound Decision Flow

[Flowchart Diagram]

Sources:[src/config.rs#96-110](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/config.rs#L96-L110)[src/handshake/server.rs#45-120](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/handshake/server.rs#L45-L120)[src/crypto/auth.rs#10-35](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/crypto/auth.rs#L10-L35)

---

## Validation Rules & Constraints

The `Config::validate()` method [src/config.rs#152-187](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/config.rs#L152-L187) enforces several security and protocol invariants.

1. PSK Strength: The PSK must be at least 32 bytes after Base64 decoding to ensure sufficient entropy for HKDF [src/config.rs#153-220](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/config.rs#L153-L220)
2. Key Lengths: X25519 keys must be exactly 32 bytes [src/config.rs#222-228](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/config.rs#L222-L228)
3. Padding Safety: `max_padding` must be greater than or equal to `min_padding`. Additionally, `max_padding` cannot exceed a threshold that would leave no room for the encrypted payload within a standard TLS record [src/config.rs#192-197](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/config.rs#L192-L197)
4. Multiplexing Constraint: `max_concurrent_streams` is currently restricted to `1`[src/config.rs#201-203](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/config.rs#L201-L203) This is a security constraint to prevent fingerprinting of the internal stream scheduler until a constant-rate multiplexer is implemented.
5. SNI Authorization: In server mode, `authorized_sni` cannot be empty [src/config.rs#177-179](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/config.rs#L177-L179) This prevents the server from accidentally acting as an open proxy for any SNI.

### Default Values

If not specified, the following defaults are applied [src/config.rs#245-265](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/config.rs#L245-L265):

- `replay_cache_path`: `replay_cache.bin`
- `strict_tls13`: `true`
- `tls_profile`: `Chrome124`
- `max_padding`: `512`
- `max_delay_ms`: `10`

Sources:[src/config.rs#152-265](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/config.rs#L152-L265)[src/protocol/data.rs#10-25](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/protocol/data.rs#L10-L25)