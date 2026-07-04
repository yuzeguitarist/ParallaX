pub mod bench;
pub mod cli;
pub mod client;
pub mod config;
pub mod crypto;
pub mod fingerprint;
pub mod handshake;
pub mod netmatrix;
pub mod probe;
pub mod process_hardening;
pub mod protocol;
pub mod runtime_guard;
pub mod secret_store;
pub mod speed;
pub mod tls;
pub mod traffic;
pub mod transport;
pub mod util;

pub const PROTOCOL_NAME: &str = "ParallaX";
pub const PROTOCOL_VERSION: u8 = 1;

/// Fuzz-only re-exports for `pub(crate)` QUIC internals that fuzz targets must
/// reach. The QUIC modules (`transport::udp::quic::*`) are deliberately
/// crate-private; this aggregator surfaces a thin shim ONLY under `--cfg fuzzing`
/// (which cargo-fuzz sets), so production API surface is unchanged.
#[cfg(fuzzing)]
pub mod quic_fuzz {
    pub use crate::transport::udp::quic::transport_params::fuzz as transport_params;
}
