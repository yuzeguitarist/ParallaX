pub mod cli;
pub mod client;
pub mod config;
pub mod crypto;
pub mod handshake;
pub mod protocol;
pub mod tls;
pub mod traffic;
pub mod transport;

pub const PROTOCOL_NAME: &str = "ParallaX";
pub const PROTOCOL_VERSION: u8 = 1;
