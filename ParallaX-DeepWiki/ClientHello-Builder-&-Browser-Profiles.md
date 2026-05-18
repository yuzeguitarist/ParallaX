# ClientHello Builder & Browser Profiles
Relevant source files

- [src/handshake/mod.rs](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/handshake/mod.rs)
- [src/tls/backend.rs](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/tls/backend.rs)
- [src/tls/client_hello.rs](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/tls/client_hello.rs)
- [src/tls/client_hello_builder.rs](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/tls/client_hello_builder.rs)
- [src/tls/mod.rs](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/tls/mod.rs)
- [src/tls/server_hello.rs](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/tls/server_hello.rs)

The ClientHello Builder is a core component of ParallaX's camouflage layer, responsible for generating TLS 1.3 `ClientHello` messages that are indistinguishable from those produced by legitimate web browsers [src/tls/client_hello_builder.rs#1-121](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/tls/client_hello_builder.rs#L1-L121) It achieves this by implementing browser-specific extension ordering, cipher suite selection, and GREASE (Generate Random Extensions And Sustain Extensibility) injection [src/tls/client_hello_builder.rs#123-173](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/tls/client_hello_builder.rs#L123-L173)

Crucially, ParallaX "hijacks" standard TLS fields to carry cryptographic material: the `random` field is used to transport the client's ephemeral X25519 public key, and the `session_id` field is used to carry the authenticated session tag [src/tls/client_hello_builder.rs#80-83](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/tls/client_hello_builder.rs#L80-L83)[src/tls/client_hello_builder.rs#62-63](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/tls/client_hello_builder.rs#L62-L63)

## Browser Profiles

ParallaX defines specific profiles to mimic the fingerprint of modern browsers. Each profile dictates the set of supported cipher suites and the exact order of TLS extensions.

| Profile | Target Browser | Characteristics |
| --- | --- | --- |
| `Safari26` | Apple Safari 26 | Specific extension order; includes `h2` and `http/1.1` ALPN [src/tls/client_hello_builder.rs#156-163](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/tls/client_hello_builder.rs#L156-L163) |
| `Chrome124` | Google Chrome 124 | Different extension ordering compared to Safari; standard Chrome cipher suites [src/tls/client_hello_builder.rs#164-171](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/tls/client_hello_builder.rs#L164-L171) |

### Cipher Suite Selection

The builder selects cipher suites based on the profile, always prepending a GREASE value to mimic real-world browser behavior [src/tls/client_hello_builder.rs#123-146](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/tls/client_hello_builder.rs#L123-L146) Supported suites include:

- `TLS_AES_128_GCM_SHA256`[src/tls/client_hello_builder.rs#16](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/tls/client_hello_builder.rs#L16-L16)
- `TLS_AES_256_GCM_SHA384`[src/tls/client_hello_builder.rs#17](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/tls/client_hello_builder.rs#L17-L17)
- `TLS_CHACHA20_POLY1305_SHA256`[src/tls/client_hello_builder.rs#18](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/tls/client_hello_builder.rs#L18-L18)

Sources:[src/tls/client_hello_builder.rs#27-33](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/tls/client_hello_builder.rs#L27-L33)[src/tls/client_hello_builder.rs#123-173](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/tls/client_hello_builder.rs#L123-L173)

## ClientHello Construction Flow

The construction process is handled by the `ClientHelloTemplate` struct, which encapsulates the target SNI, the X25519 public key, and the desired `BrowserProfile`[src/tls/client_hello_builder.rs#46-50](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/tls/client_hello_builder.rs#L46-L50)

### Data Flow: From Template to Signed Record

The following diagram illustrates how `ClientHelloTemplate` methods transform raw configuration into a wire-format TLS record.

Diagram: ClientHello Construction Pipeline

[Flowchart Diagram]

Sources:[src/tls/client_hello_builder.rs#46-67](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/tls/client_hello_builder.rs#L46-L67)[src/tls/client_hello_builder.rs#78-108](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/tls/client_hello_builder.rs#L78-L108)

### Key Functions

- `build_unsigned`: Constructs the basic TLS record, populating the `random` field with the X25519 public key and setting the `session_id` to 32 bytes of zeros as a placeholder [src/tls/client_hello_builder.rs#66-121](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/tls/client_hello_builder.rs#L66-L121)
- `build_signed`: Calls `build_unsigned` and then invokes the authentication subsystem to overwrite the `session_id` placeholder with a cryptographic tag [src/tls/client_hello_builder.rs#53-64](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/tls/client_hello_builder.rs#L53-L64)
- `grease_value`: Generates a valid GREASE constant (e.g., `0x1A1A`, `0x2A2A`) to prevent middlebox ossification [src/tls/client_hello_builder.rs#215-220](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/tls/client_hello_builder.rs#L215-L220)

Sources:[src/tls/client_hello_builder.rs#52-121](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/tls/client_hello_builder.rs#L52-L121)

## The Camouflage Backend

The `CamouflageTlsBackend` trait abstracts the mechanism used to generate the handshake [src/tls/backend.rs#41-50](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/tls/backend.rs#L41-L50)

### NativeCamouflageBackend

The `NativeCamouflageBackend` is the default implementation. It uses the internal `ClientHelloBuilder` logic to generate the signed record directly [src/tls/backend.rs#52-67](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/tls/backend.rs#L52-L67)

Diagram: Backend Interaction

[Flowchart Diagram]

Sources:[src/tls/backend.rs#55-67](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/tls/backend.rs#L55-L67)[src/tls/client_hello_builder.rs#53-64](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/tls/client_hello_builder.rs#L53-L64)

## Field Hijacking Details

To avoid detection while maintaining protocol efficiency, ParallaX repurposes standard TLS 1.3 fields:

1. Random (32 bytes): In standard TLS, this is entropy. ParallaX places the X25519 public key here [src/tls/client_hello_builder.rs#80-81](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/tls/client_hello_builder.rs#L80-L81) This allows the server to derive the session key immediately upon receiving the `ClientHello`.
2. Session ID (32 bytes): In TLS 1.3, this is a legacy field. ParallaX uses it for Handshake Authentication. The `sign_client_hello_session_id` function replaces the zeros with a tag derived from the PSK and the transcript [src/tls/client_hello_builder.rs#62-63](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/tls/client_hello_builder.rs#L62-L63)

### Parsing Logic

The server uses `parse_client_hello` to extract these hijacked fields for validation [src/tls/client_hello.rs#40-119](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/tls/client_hello.rs#L40-L119) It identifies the `session_id_range` and extracts the `client_random` to recover the X25519 key [src/tls/client_hello.rs#66-71](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/tls/client_hello.rs#L66-L71)

Sources:[src/tls/client_hello.rs#15-22](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/tls/client_hello.rs#L15-L22)[src/tls/client_hello.rs#40-71](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/tls/client_hello.rs#L40-L71)[src/tls/client_hello_builder.rs#78-83](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/tls/client_hello_builder.rs#L78-L83)