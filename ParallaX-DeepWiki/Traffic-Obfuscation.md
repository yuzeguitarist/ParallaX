# Traffic Obfuscation
Relevant source files

- [src/config.rs](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/config.rs)
- [src/traffic.rs](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/traffic.rs)

The Traffic Obfuscation subsystem in ParallaX is responsible for defeating Traffic Analysis (TA) by altering the observable characteristics of the encrypted data stream. While the [TLS Camouflage Layer](#4) masks the initial handshake, this subsystem focuses on the subsequent data relay phase, mitigating risks from side-channel analysis such as packet length distribution and inter-arrival timing.

The system employs three primary strategies to achieve analysis resistance:

1. Padding: Normalizing packet sizes to match common network distributions.
2. Timing Jitter: Decoupling application-layer events from network-layer emissions.
3. Cover Traffic: Maintaining a baseline of activity even when no application data is flowing.

### Architecture Overview

Obfuscation is governed by the `TrafficConfig`[src/config.rs#112-128](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/config.rs#L112-L128) which is translated into active profiles during the session establishment. These profiles are applied within the data relay loops of both the client and server.

#### Obfuscation Logic Flow

The following diagram illustrates how raw application data is transformed into an obfuscated stream.

Data Obfuscation Pipeline

[Flowchart Diagram]

Sources:[src/traffic.rs#54-67](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/traffic.rs#L54-L67)[src/traffic.rs#121-136](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/traffic.rs#L121-L136)

---

### Padding & Timing Profiles

The `PaddingProfile` and `TimingProfile` structures are the core engines for per-packet obfuscation. Unlike simple constant padding, ParallaX uses statistical distributions derived from common network traffic.

- Padding Distribution: 55% of packets are padded to match `OBSERVED_PACKET_TARGETS`, which include common MTU sizes like 1440, 1460, and 1500 bytes [src/traffic.rs#36-38](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/traffic.rs#L36-L38)[src/traffic.rs#77-84](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/traffic.rs#L77-L84)
- Timing Distribution: 60% of delays are sampled from `OBSERVED_DELAY_MS`[src/traffic.rs#40](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/traffic.rs#L40-L40) which mimics realistic network jitter [src/traffic.rs#128-132](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/traffic.rs#L128-L132)
- Framing: A 2-byte big-endian field at the end of every padded frame indicates the length of the trailing random noise, allowing the receiver to reconstruct the original payload [src/traffic.rs#65](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/traffic.rs#L65-L65)[src/traffic.rs#103-105](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/traffic.rs#L103-L105)

For implementation details on the statistical distributions and the `DataRecordCodec` integration, see [Padding & Timing Profiles (#5.1)].

Sources:[src/traffic.rs#18-28](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/traffic.rs#L18-L28)[src/traffic.rs#36-40](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/traffic.rs#L36-L40)[src/traffic.rs#54-111](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/traffic.rs#L54-L111)

---

### Cover Traffic

Cover traffic (dummy traffic) ensures that an observer cannot distinguish between an idle connection and an active one. This is critical for preventing "on/off" pattern detection.

- Generation: The `CoverTrafficProfile`[src/traffic.rs#30-34](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/traffic.rs#L30-L34) manages the interval between dummy packets.
- Configuration: Intervals are defined by `cover_min_interval_ms` and `cover_max_interval_ms` in the `TrafficConfig`[src/config.rs#122-125](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/config.rs#L122-L125)
- Behavior: When the relay loop is idle, the system generates dummy `DataRecord` frames filled with random bytes, ensuring the connection maintains a consistent cryptographic heartbeat.

For details on the background generation loop and configuration parameters, see [Cover Traffic (#5.2)].

Sources:[src/traffic.rs#139-163](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/traffic.rs#L139-L163)[src/config.rs#112-128](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/config.rs#L112-L128)

---

### Entity Mapping

This table maps the conceptual obfuscation components to their specific implementations in the codebase.

| Concept | Code Entity | File Path |
| --- | --- | --- |
| Configuration | `TrafficConfig` | [src/config.rs#112-128](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/config.rs#L112-L128) |
| Packet Shaping | `PaddingProfile` | [src/traffic.rs#19-22](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/traffic.rs#L19-L22) |
| Timing Jitter | `TimingProfile` | [src/traffic.rs#25-28](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/traffic.rs#L25-L28) |
| Dummy Traffic | `CoverTrafficProfile` | [src/traffic.rs#31-34](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/traffic.rs#L31-L34) |
| Padding Logic | `PaddingProfile::apply` | [src/traffic.rs#54-67](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/traffic.rs#L54-L67) |
| Unpadding Logic | `PaddingProfile::remove` | [src/traffic.rs#98-110](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/traffic.rs#L98-L110) |

Obfuscation Component Relationship

[Class Diagram]

Sources:[src/config.rs#190-205](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/config.rs#L190-L205)[src/traffic.rs#42-163](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/traffic.rs#L42-L163)