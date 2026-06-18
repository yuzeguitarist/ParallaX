//! Safari-faithful ClientHello shaping (ParallaX fork addition).
//!
//! This module defines [`SafariChProfile`], a caller-supplied description of an
//! exact ClientHello wire shape (cipher-suite list, extension order incl. raw
//! GREASE/legacy extensions, ALPN override). When a [`crate::ClientConfig`]
//! carries `Some(profile)`, the ClientHello assembly in
//! [`crate::client`]`::hs::emit_client_hello_for_retry` substitutes the
//! profile's shape onto the typed `ClientHelloPayload` *before* the message is
//! frozen and hashed into the transcript, so the wire bytes and the Finished-MAC
//! transcript stay byte-identical (the make-or-break invariant).
//!
//! This is COLD-START only: the profile never injects `pre_shared_key` or
//! `early_data`; resumption must be disabled on the config that uses it.

use alloc::vec::Vec;

use crate::enums::CipherSuite;
use crate::msgs::enums::ExtensionType;

/// One entry in a Safari extension plan: either a rustls-managed extension whose
/// body is encoded from the typed `ClientExtensions` field, or a raw extension
/// (typ + verbatim body bytes) that rustls has no field for (e.g. GREASE
/// extensions, or legacy `extended_master_secret` / `renegotiation_info` when
/// the capture switch enables them).
#[derive(Clone, Debug)]
pub enum SafariExt {
    /// Encode the named extension from the typed `ClientExtensions` field.
    ///
    /// The field MUST be populated (`Some`) by the assembly path, otherwise it
    /// encodes to nothing and silently drops out of the wire order.
    Managed(ExtensionType),

    /// Emit a raw extension verbatim: `(extension_type, body_bytes)`.
    ///
    /// The encoder writes `type` (u16) then a u16 length prefix then `body`.
    /// Used for GREASE (len 0 / len 1) and capture-gated legacy extensions.
    Raw(u16, Vec<u8>),
}

/// A complete description of a Safari-faithful ClientHello shape.
///
/// All fields are overrides applied to the rustls-generated ClientHello; any
/// part left as the natural rustls value is unchanged.
#[derive(Clone, Debug)]
pub struct SafariChProfile {
    /// Exact cipher-suite list to put on the wire, including GREASE
    /// (`CipherSuite::Unknown(..)`) and Apple's duplicate `0x0805`. Replaces the
    /// rustls protocol-filtered list verbatim.
    pub cipher_suites: Vec<CipherSuite>,

    /// Exact extension ordering plan. When present it fully replaces the rustls
    /// `order_seed` shuffle and the force-PSK-last logic: extensions are emitted
    /// in exactly this order. `pre_shared_key` is NOT part of cold-start, so it
    /// must not appear here.
    pub extension_plan: Vec<SafariExt>,

    /// ALPN protocols to advertise (e.g. `[b"h3"]`). Replaces whatever ALPN the
    /// config carried.
    pub alpn: Vec<Vec<u8>>,

    /// GREASE key-share group codepoint to PREPEND to the real key shares. The
    /// entry carries a single throwaway byte; it never displaces the real share.
    pub key_share_grease_group: u16,
}
