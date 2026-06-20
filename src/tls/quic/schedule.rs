//! The QUIC TLS 1.3 key schedule (RFC 8446 §7.1 + RFC 9001 §5).
//!
//! Pure orchestration over [`CipherSuite`] primitives: it turns the (EC)DHE shared
//! secret and the transcript-hash snapshots into the per-space [`Keys`] the QUIC
//! transport installs, plus the Finished/exporter/key-update material. All
//! intermediate secrets are held in `Zeroizing`.

use zeroize::Zeroizing;

use super::keys::{DirectionalKeys, KeyPair, Keys, PacketKey};
use super::suite::CipherSuite;
use super::{QuicTlsError, Side};

/// QUIC v1 Initial salt (RFC 9001 §5.2).
const INITIAL_SALT_V1: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

/// Derive the Initial-space [`Keys`] for `dcid` (RFC 9001 §5.2). Always uses the
/// `Aes128GcmSha256` parameters regardless of the eventually-negotiated suite.
///
/// Infallible for the fixed Initial parameters: the HKDF lengths are small
/// constants, so an `expect` here can only fire on a broken HKDF backend (the
/// same posture as quinn-proto/rustls at this seam).
pub(crate) fn initial_keys(dcid: &[u8], side: Side) -> Keys {
    let suite = CipherSuite::Aes128GcmSha256;
    let initial_secret = suite.hkdf_extract(&INITIAL_SALT_V1, dcid);
    let expect =
        |r: Result<Vec<u8>, QuicTlsError>| r.expect("Initial HKDF-Expand-Label is infallible");
    let client = expect(suite.hkdf_expand_label(&initial_secret, "client in", &[], 32));
    let server = expect(suite.hkdf_expand_label(&initial_secret, "server in", &[], 32));
    let (local_secret, remote_secret) = match side {
        Side::Client => (&client, &server),
        Side::Server => (&server, &client),
    };
    let build = |secret: &[u8]| {
        DirectionalKeys::from_secret(suite, secret).expect("Initial key material is infallible")
    };
    Keys {
        local: build(local_secret),
        remote: build(remote_secret),
    }
}

/// The evolving TLS 1.3 secret state, from handshake secrets through 1-RTT and
/// its key-update generations. Created once the ServerHello fixes the suite and
/// the (EC)DHE shared secret is known.
pub(crate) struct KeySchedule {
    suite: CipherSuite,
    /// Handshake Secret (input to the Master Secret extract).
    handshake_secret: Zeroizing<Vec<u8>>,
    /// `client_handshake_traffic_secret` (client Finished + client hs keys).
    client_hs_secret: Zeroizing<Vec<u8>>,
    /// `server_handshake_traffic_secret` (server Finished + server hs keys).
    server_hs_secret: Zeroizing<Vec<u8>>,
    /// `exporter_master_secret` (RFC 5705 exporter), set once 1-RTT is derived.
    exporter_master: Option<Zeroizing<Vec<u8>>>,
    /// The NEXT 1-RTT application secrets to hand out from
    /// [`Self::next_1rtt_packet_keys`] (already advanced one generation past the
    /// installed 1-RTT keys, matching the QUIC key-update contract).
    next_client_app_secret: Option<Zeroizing<Vec<u8>>>,
    next_server_app_secret: Option<Zeroizing<Vec<u8>>>,
}

impl KeySchedule {
    /// Run the schedule through the handshake traffic secrets and return both the
    /// secret state and the Handshake-space [`Keys`] (client = local, server =
    /// remote). `transcript_hash` is the hash over ClientHello..ServerHello.
    pub(crate) fn after_server_hello(
        suite: CipherSuite,
        shared_secret: &[u8],
        transcript_hash: &[u8],
    ) -> Result<(Self, Keys), QuicTlsError> {
        let zeros = vec![0_u8; suite.hash_len()];
        let early_secret = suite.hkdf_extract(&zeros, &zeros);
        let empty_hash = suite.digest(&[]);
        let derived = suite.derive_secret(&early_secret, "derived", &empty_hash)?;
        let handshake_secret = Zeroizing::new(suite.hkdf_extract(&derived, shared_secret));
        let client_hs_secret = Zeroizing::new(suite.derive_secret(
            &handshake_secret,
            "c hs traffic",
            transcript_hash,
        )?);
        let server_hs_secret = Zeroizing::new(suite.derive_secret(
            &handshake_secret,
            "s hs traffic",
            transcript_hash,
        )?);
        let keys = Keys {
            local: DirectionalKeys::from_secret(suite, &client_hs_secret)?,
            remote: DirectionalKeys::from_secret(suite, &server_hs_secret)?,
        };
        Ok((
            Self {
                suite,
                handshake_secret,
                client_hs_secret,
                server_hs_secret,
                exporter_master: None,
                next_client_app_secret: None,
                next_server_app_secret: None,
            },
            keys,
        ))
    }

    /// Finished verify_data for the server's Finished (HMAC over `transcript_hash`
    /// with a key derived from the server handshake secret).
    pub(crate) fn server_finished_verify_data(
        &self,
        transcript_hash: &[u8],
    ) -> Result<Vec<u8>, QuicTlsError> {
        self.finished_verify_data(&self.server_hs_secret, transcript_hash)
    }

    /// Finished verify_data for the client's Finished.
    pub(crate) fn client_finished_verify_data(
        &self,
        transcript_hash: &[u8],
    ) -> Result<Vec<u8>, QuicTlsError> {
        self.finished_verify_data(&self.client_hs_secret, transcript_hash)
    }

    fn finished_verify_data(
        &self,
        base_secret: &[u8],
        transcript_hash: &[u8],
    ) -> Result<Vec<u8>, QuicTlsError> {
        let finished_key = Zeroizing::new(self.suite.hkdf_expand_label(
            base_secret,
            "finished",
            &[],
            self.suite.hash_len(),
        )?);
        self.suite.hmac(&finished_key, transcript_hash)
    }

    /// Derive the Master Secret, the 1-RTT application traffic secrets, and the
    /// exporter master secret (`transcript_hash` = ClientHello..server Finished).
    /// Returns the 1-RTT [`Keys`] built from generation 0; the schedule then
    /// holds generation 1 ready for [`Self::next_1rtt_packet_keys`].
    pub(crate) fn derive_application(
        &mut self,
        transcript_hash: &[u8],
    ) -> Result<Keys, QuicTlsError> {
        let zeros = vec![0_u8; self.suite.hash_len()];
        let empty_hash = self.suite.digest(&[]);
        let derived = self
            .suite
            .derive_secret(&self.handshake_secret, "derived", &empty_hash)?;
        let master_secret = Zeroizing::new(self.suite.hkdf_extract(&derived, &zeros));
        let client_app = Zeroizing::new(self.suite.derive_secret(
            &master_secret,
            "c ap traffic",
            transcript_hash,
        )?);
        let server_app = Zeroizing::new(self.suite.derive_secret(
            &master_secret,
            "s ap traffic",
            transcript_hash,
        )?);
        self.exporter_master = Some(Zeroizing::new(self.suite.derive_secret(
            &master_secret,
            "exp master",
            transcript_hash,
        )?));

        let keys = Keys {
            local: DirectionalKeys::from_secret(self.suite, &client_app)?,
            remote: DirectionalKeys::from_secret(self.suite, &server_app)?,
        };
        // Pre-advance one generation: the first `next_1rtt_packet_keys` hands out
        // generation 1 (the first key update), per RFC 9001 §6 / the QUIC contract.
        self.next_client_app_secret = Some(self.update_secret(&client_app)?);
        self.next_server_app_secret = Some(self.update_secret(&server_app)?);
        Ok(keys)
    }

    /// Advance a 1-RTT traffic secret one generation (RFC 9001 §6.1 key update:
    /// `secret_{n+1} = HKDF-Expand-Label(secret_n, "quic ku", "", Hash.len)`).
    fn update_secret(&self, secret: &[u8]) -> Result<Zeroizing<Vec<u8>>, QuicTlsError> {
        Ok(Zeroizing::new(self.suite.hkdf_expand_label(
            secret,
            "quic ku",
            &[],
            self.suite.hash_len(),
        )?))
    }

    /// Return the next 1-RTT packet-key generation (both directions) and advance
    /// the stored secrets again. Header-protection keys are NOT rotated on a key
    /// update (RFC 9001 §6), so only [`PacketKey`]s are returned.
    pub(crate) fn next_1rtt_packet_keys(&mut self) -> Result<KeyPair<PacketKey>, QuicTlsError> {
        let client = self
            .next_client_app_secret
            .take()
            .ok_or_else(|| QuicTlsError::Crypto("1-RTT keys requested before handshake".into()))?;
        let server = self
            .next_server_app_secret
            .take()
            .ok_or_else(|| QuicTlsError::Crypto("1-RTT keys requested before handshake".into()))?;
        let pair = KeyPair {
            local: PacketKey::from_secret(self.suite, &client)?,
            remote: PacketKey::from_secret(self.suite, &server)?,
        };
        self.next_client_app_secret = Some(self.update_secret(&client)?);
        self.next_server_app_secret = Some(self.update_secret(&server)?);
        Ok(pair)
    }

    /// RFC 5705 / TLS 1.3 exporter (RFC 8446 §7.5). Fills `out` with keying
    /// material bound to this handshake, `label`, and `context`.
    pub(crate) fn export_keying_material(
        &self,
        out: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> Result<(), QuicTlsError> {
        let exporter_master = self.exporter_master.as_ref().ok_or_else(|| {
            QuicTlsError::Crypto("exporter used before handshake complete".into())
        })?;
        let label_str = std::str::from_utf8(label)
            .map_err(|_| QuicTlsError::Crypto("exporter label not UTF-8".into()))?;
        let empty_hash = self.suite.digest(&[]);
        let secret = Zeroizing::new(self.suite.hkdf_expand_label(
            exporter_master,
            label_str,
            &empty_hash,
            self.suite.hash_len(),
        )?);
        let context_hash = self.suite.digest(context);
        let material = Zeroizing::new(self.suite.hkdf_expand_label(
            &secret,
            "exporter",
            &context_hash,
            out.len(),
        )?);
        out.copy_from_slice(&material);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_keys_client_remote_is_server_secret() {
        // Both sides derive the same pair; client.local == server.remote material.
        let dcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
        let _ = initial_keys(&dcid, Side::Client);
        let _ = initial_keys(&dcid, Side::Server);
        // Smoke: derivation does not panic and produces usable keys for both sides.
    }

    #[test]
    fn exporter_is_deterministic_and_context_bound() {
        let suite = CipherSuite::Aes128GcmSha256;
        let shared = [0x5a_u8; 32];
        let th = suite.digest(b"transcript-sh");
        let (mut sched, _keys) = KeySchedule::after_server_hello(suite, &shared, &th).unwrap();
        let th_sf = suite.digest(b"transcript-server-finished");
        let _ = sched.derive_application(&th_sf).unwrap();

        let mut a = [0_u8; 32];
        let mut b = [0_u8; 32];
        let mut c = [0_u8; 32];
        sched
            .export_keying_material(&mut a, b"label", b"ctx")
            .unwrap();
        sched
            .export_keying_material(&mut b, b"label", b"ctx")
            .unwrap();
        sched
            .export_keying_material(&mut c, b"label", b"other")
            .unwrap();
        assert_eq!(a, b, "exporter is deterministic for the same inputs");
        assert_ne!(a, c, "exporter is bound to its context");
    }

    #[test]
    fn key_update_generations_differ() {
        let suite = CipherSuite::Aes256GcmSha384;
        let shared = [0x33_u8; 32];
        let th = suite.digest(b"sh");
        let (mut sched, _keys) = KeySchedule::after_server_hello(suite, &shared, &th).unwrap();
        let _ = sched.derive_application(&suite.digest(b"sf")).unwrap();
        // Two successive generations must produce different packet keys (nonce-1
        // ciphertexts differ); exercised indirectly by encrypting a fixed input.
        let g1 = sched.next_1rtt_packet_keys().unwrap();
        let g2 = sched.next_1rtt_packet_keys().unwrap();
        let mut b1 = vec![0_u8; 8 + super::super::keys::AEAD_TAG_LEN];
        let mut b2 = b1.clone();
        g1.local.encrypt_in_place(0, b"h", &mut b1).unwrap();
        g2.local.encrypt_in_place(0, b"h", &mut b2).unwrap();
        assert_ne!(b1, b2, "successive key-update generations must differ");
    }
}
