# HTTP/3 Fingerprint Façade

> Navigation: [Index](README.md) | [HTTP/2 Fingerprinting](HTTP-2-Fingerprinting.md) | [QUIC Fast Plane](QUIC-Fast-Plane.md) | [TLS Camouflage Layer](TLS-Camouflage-Layer.md)

## Purpose

The experimental QUIC fast plane carries its relay inside a masquerading HTTP/3
face. `src/fingerprint/http3.rs` is the pure-library codec that builds and parses
the H3 frames and QPACK field sections needed to make that face look like Safari 26,
mirroring what [HTTP/2 Fingerprinting](HTTP-2-Fingerprinting.md) does for the TCP
path. It builds and parses bytes only — it does not own the QUIC connection, streams,
probe, or relay (that is [QUIC Fast Plane](QUIC-Fast-Plane.md)).

## Scope

| In scope | Out of scope |
|---|---|
| H3 frame encode/decode (RFC 9114). | QUIC connection / stream orchestration. |
| Safari-26 SETTINGS, control + QPACK uni-stream shaping. | The QUIC transport (`src/transport/udp/quic/`). |
| Static-only QPACK field sections (RFC 9204). | The QPACK **dynamic** table is advertised for Safari parity (`QPACK_MAX_TABLE_CAPACITY = 16383` in SETTINGS) but never populated — Required Insert Count stays 0. ParallaX controls both ends, so no dynamic entries are inserted. |

## QPACK subset

- Full QPACK static table (RFC 9204 Appendix A, indices `0..=98`).
- Huffman encode/decode (RFC 7541).
- Static-only field sections: the field-section prefix is `0x00 0x00` (Required
  Insert Count 0, Delta Base 0). The dynamic table is explicitly never used.
- Per-field encoding choice: static full match → indexed; static name match →
  name-reference + Huffman value; otherwise Huffman name + Huffman value.

## H3 frame and stream constants

| Name | Value |
|---|---|
| `FRAME_TYPE_DATA` | `0x00` |
| `FRAME_TYPE_HEADERS` | `0x01` |
| `FRAME_TYPE_SETTINGS` | `0x04` |
| `STREAM_TYPE_CONTROL` | `0x00` |
| `STREAM_TYPE_QPACK_ENCODER` | `0x02` |
| `STREAM_TYPE_QPACK_DECODER` | `0x03` |
| `MAX_PAYLOAD_LEN` | `1 << 20` (1 MiB defensive bound) |

## Safari-26 SETTINGS

On the control stream, the SETTINGS frame carries exactly three settings, in this
wire order:

1. `SETTINGS_QPACK_MAX_TABLE_CAPACITY` (`0x01`) = `16383`
2. `SETTINGS_QPACK_BLOCKED_STREAMS` (`0x07`) = `100`
3. A per-connection GREASE setting: a reserved id of the form `0x1f·N + 0x21` with
   a random value.

Notably Safari does **not** send `MAX_FIELD_SECTION_SIZE` (`0x06`); the codec omits
it deliberately. `is_safari26_settings()` validates this exact shape.

## Safari-26 request fields

The request HEADERS frame uses Safari's exact field order. The pseudo-header order
is `:method :scheme :authority :path` (authority before path, matching the H2
main-document order), followed by `sec-fetch-dest`, `user-agent`, `accept`,
`sec-fetch-site`, `sec-fetch-mode`, `accept-language`, `priority`, `accept-encoding`.
All values are hardcoded except `:authority`, which varies per request, and
`accept-language`, which defaults to the same Safari-like value as the HTTP/2
façade but may be overridden with `client.accept_language` so the two faces
agree.

## API surface

- Frames: `encode_frame`, `decode_frame`.
- Settings: `safari26_settings`, `safari26_settings_frame`, `parse_settings_payload`,
  `is_safari26_settings`.
- Headers: `safari26_headers_frame(authority)`,
  `safari26_headers_frame_with_language(authority, accept_language)`,
  `safari26_request_fields(authority)`,
  `safari26_request_fields_with_language(authority, accept_language)`, and
  `response_status_200_headers_frame`.
- QPACK: `encode_field_section`, `decode_field_section`.

## Operational meaning

Like the HTTP/2 façade, this is camouflage shaping, not the data plane. When the
QUIC plane is enabled, the relay rides reliable QUIC streams behind this H3 face;
the actual payload is the AEAD-sealed ParallaX data described in
[Protocol Commands & Data Records](Protocol-Commands-&-Data-Records.md).

## Drift risks

Safari H3 SETTINGS, the request field order, and QPACK choices can change with
OS/browser updates. The measured ground truth for the app-layer shape is captured
separately; when it is refreshed, update this page and the parity tests together,
and keep it aligned with [HTTP/2 Fingerprinting](HTTP-2-Fingerprinting.md) and
[QUIC Fast Plane](QUIC-Fast-Plane.md).
