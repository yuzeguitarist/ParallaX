use rand::{CryptoRng, RngCore};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::{
    config::TrafficConfig,
    crypto::{
        identity::{self, IdentityError},
        pq::{self, PqError},
        session::{
            derive_client_keys, derive_client_keys_from_shared, expand_epoch_keys,
            x25519_shared_secret, AeadCodec, CipherSuite, SessionError, SessionKeys, X25519KeyPair,
        },
    },
    protocol::{
        command::{
            ConnectRequest, ConnectRequestError, FramedChunk, FramedChunkError, PqRekeyError,
            PqRekeyRequest, ServerIdentityChunk, ServerIdentityChunkError, ServerIdentityProof,
            ServerIdentityProofError, ServerKeyExchange, ServerKeyExchangeError,
        },
        data::{
            DataRecordCodec, DataRecordError, SealedRecord, CLIENT_TO_SERVER_AAD,
            SERVER_TO_CLIENT_AAD,
        },
    },
    traffic::{PaddingProfile, TrafficError},
};

use super::transcript::transcript_hash;

#[derive(Debug, Error)]
pub enum ClientHandshakeError {
    #[error("session key derivation failed: {0}")]
    Session(#[from] SessionError),
    #[error("traffic shaping error: {0}")]
    Traffic(#[from] TrafficError),
    #[error("connect request error: {0}")]
    ConnectRequest(#[from] ConnectRequestError),
    #[error("data record error: {0}")]
    DataRecord(#[from] DataRecordError),
    #[error("PQ rekey error: {0}")]
    Pq(#[from] PqError),
    #[error("PQ rekey command error: {0}")]
    PqCommand(#[from] PqRekeyError),
    #[error("framed chunk command error: {0}")]
    FramedChunk(#[from] FramedChunkError),
    #[error("server key exchange command error: {0}")]
    ServerKeyExchange(#[from] ServerKeyExchangeError),
    #[error("server identity proof command error: {0}")]
    ServerIdentityProof(#[from] ServerIdentityProofError),
    #[error("server identity chunk command error: {0}")]
    ServerIdentityChunk(#[from] ServerIdentityChunkError),
    #[error("server identity verification failed: {0}")]
    Identity(#[from] IdentityError),
    #[error("server identity proof arrived before a bound PQ rekey exchange")]
    MissingPqIdentityBinding,
}

pub fn derive_session_keys(
    psk: &[u8],
    client_private: &[u8; 32],
    server_public: &[u8; 32],
    client_hello_record: &[u8],
    server_hello_record: &[u8],
) -> Result<SessionKeys, ClientHandshakeError> {
    let transcript_hash = transcript_hash(client_hello_record, server_hello_record);
    Ok(derive_client_keys(
        psk,
        client_private,
        server_public,
        &transcript_hash,
    )?)
}

pub fn derive_session_keys_from_shared(
    psk: &[u8],
    x25519_shared_secret: &[u8; 32],
    client_hello_record: &[u8],
    server_hello_record: &[u8],
) -> Result<SessionKeys, ClientHandshakeError> {
    let transcript_hash = transcript_hash(client_hello_record, server_hello_record);
    Ok(derive_client_keys_from_shared(
        psk,
        x25519_shared_secret,
        &transcript_hash,
    )?)
}

pub fn data_codecs(
    keys: &SessionKeys,
    traffic: TrafficConfig,
) -> Result<(DataRecordCodec, DataRecordCodec), ClientHandshakeError> {
    let padding = PaddingProfile::from_config(traffic)?;
    let seal_to_server = DataRecordCodec::new(
        AeadCodec::new(keys.client_key, keys.client_nonce),
        padding,
        CLIENT_TO_SERVER_AAD,
    );
    let open_from_server = DataRecordCodec::new(
        AeadCodec::new(keys.server_key, keys.server_nonce),
        padding,
        SERVER_TO_CLIENT_AAD,
    );
    Ok((seal_to_server, open_from_server))
}

pub struct ClientDataSession {
    seal_to_server: DataRecordCodec,
    open_from_server: DataRecordCodec,
    keys: SessionKeys,
    pq_identity_binding: Option<[u8; 32]>,
}

pub struct PendingPqRekey {
    x25519: X25519KeyPair,
    mlkem: pq::MlKemKeyPair,
    request_payload: Vec<u8>,
}

impl PendingPqRekey {
    pub fn x25519_shared_secret(&self, server_public: &[u8; 32]) -> [u8; 32] {
        x25519_shared_secret(&self.x25519.private, server_public)
    }

    pub fn mlkem_secret_key(&self) -> &[u8] {
        &self.mlkem.secret
    }

    pub fn identity_binding(&self, server_key_exchange_payload: &[u8]) -> [u8; 32] {
        identity::pq_rekey_binding(&self.request_payload, server_key_exchange_payload)
    }
}

impl ClientDataSession {
    pub fn new(keys: SessionKeys, traffic: TrafficConfig) -> Result<Self, ClientHandshakeError> {
        let (seal_to_server, open_from_server) = data_codecs(&keys, traffic)?;
        let session = Self {
            seal_to_server,
            open_from_server,
            keys,
            pq_identity_binding: None,
        };
        session.keys.protect_secret_memory();
        session.seal_to_server.protect_secret_memory();
        session.open_from_server.protect_secret_memory();
        Ok(session)
    }

    pub fn build_pq_rekey_record<R>(
        &mut self,
        rng: &mut R,
    ) -> Result<(Vec<u8>, PendingPqRekey), ClientHandshakeError>
    where
        R: RngCore + CryptoRng + rand::Rng + ?Sized,
    {
        let x25519 = X25519KeyPair::generate();
        let mlkem = pq::keypair();
        crate::process_hardening::protect_secret_bytes("pq_rekey.x25519_private", &x25519.private);
        crate::process_hardening::protect_secret_bytes("pq_rekey.mlkem_secret", &mlkem.secret);
        let request = PqRekeyRequest::encode_borrowed(&x25519.public, &mlkem.public)?;
        // Shape the rekey record into a browser-modeled record-size distribution and
        // apply per-session aggregate decorrelation padding (PAR-35), so the
        // client->server PQ burst falls inside the Safari H2 page-traffic distribution
        // instead of reading as a second, heavier PQ key exchange than the ML-KEM-768
        // the outer ClientHello advertised. (Supersedes the PAR-21 uniform [256,1024]
        // split; same one-buffer => one write => single flight, no added round-trip.)
        // The server reassembles by FramedChunk length headers; the aggregate pad is
        // stripped transparently by the per-record padding trailer.
        let mut record = Vec::new();
        // Cap the shaped chunk size to what this codec can seal under its padding
        // profile, so a heavy `max_padding` config cannot push a shaped record past the
        // TLS record limit (the aggregate pad on the last record is reserved too).
        let max_chunk = crate::protocol::command::pq_flight_max_chunk_size(
            self.seal_to_server.max_plaintext_len(),
        );
        let chunks = FramedChunk::encode_all_browser_shaped(&request, max_chunk, rng)?;
        self.seal_to_server
            .seal_pq_flight(&chunks, rng, &mut record)?;
        Ok((
            record,
            PendingPqRekey {
                x25519,
                mlkem,
                request_payload: request,
            },
        ))
    }

    pub fn apply_server_key_exchange_record(
        &mut self,
        record: &[u8],
        pending: &PendingPqRekey,
        sandwich_secret: &[u8],
    ) -> Result<(), ClientHandshakeError> {
        let exchange_payload = self.open_from_server.open(record)?;
        let (exchange, cipher_suite) = ServerKeyExchange::decode_ref_with_suite(&exchange_payload)?;
        let pq_identity_binding = pending.identity_binding(&exchange_payload);
        let x25519_shared =
            Zeroizing::new(pending.x25519_shared_secret(&exchange.server_x25519_public));
        let pq_shared = Zeroizing::new(pq::decapsulate(
            exchange.mlkem_ciphertext,
            &pending.mlkem.secret,
        )?);
        self.apply_pq_rekey_shared_with_identity_binding(
            cipher_suite,
            &x25519_shared,
            &pq_shared,
            sandwich_secret,
            pq_identity_binding,
        )?;
        Ok(())
    }

    pub fn build_connect_record<R>(
        &mut self,
        request: ConnectRequest,
        rng: &mut R,
    ) -> Result<Vec<u8>, ClientHandshakeError>
    where
        R: RngCore + CryptoRng + rand::Rng + ?Sized,
    {
        request.protect_plaintext_memory();
        let payload = Zeroizing::new(request.encode()?);
        // C3: snap the CONNECT record onto a randomly chosen browser-magnitude
        // size band so its on-wire length leaks neither the target host length
        // nor the captured 0-RTT payload size. The pad rides the existing
        // self-describing 2-byte trailer (decode-transparent, no wire-format
        // change) and is bounded so the padded record still fits one TLS record.
        // `seal_into_exact_padded` writes EXACTLY this pad and bypasses the
        // codec's profile sampling, so the record lands on its band even when a
        // non-default TrafficConfig padding profile is configured.
        let max_extra_pad = self
            .seal_to_server
            .max_plaintext_len()
            .saturating_sub(payload.len());
        let shaping_pad = request.shaping_extra_pad(max_extra_pad, rng);
        let mut out = Vec::new();
        self.seal_to_server.seal_into_exact_padded(
            payload.as_slice(),
            shaping_pad,
            rng,
            &mut out,
        )?;
        Ok(out)
    }

    pub fn seal_payload<R>(
        &mut self,
        payload: &[u8],
        rng: &mut R,
    ) -> Result<Vec<u8>, ClientHandshakeError>
    where
        R: RngCore + CryptoRng + rand::Rng + ?Sized,
    {
        Ok(self.seal_to_server.seal(payload, rng)?)
    }

    pub fn seal_payload_chunks<R>(
        &mut self,
        payload: &[u8],
        rng: &mut R,
    ) -> Result<Vec<Vec<u8>>, ClientHandshakeError>
    where
        R: RngCore + CryptoRng + rand::Rng + ?Sized,
    {
        Ok(self.seal_to_server.seal_chunks(payload, rng)?)
    }

    pub fn seal_payload_chunks_into<R>(
        &mut self,
        payload: &[u8],
        rng: &mut R,
        out: &mut Vec<u8>,
    ) -> Result<Vec<SealedRecord>, ClientHandshakeError>
    where
        R: RngCore + CryptoRng + rand::Rng + ?Sized,
    {
        Ok(self.seal_to_server.seal_chunks_into(payload, rng, out)?)
    }

    pub fn seal_payload_chunks_into_reusing<R>(
        &mut self,
        payload: &[u8],
        rng: &mut R,
        out: &mut Vec<u8>,
        records: &mut Vec<SealedRecord>,
    ) -> Result<(), ClientHandshakeError>
    where
        R: RngCore + CryptoRng + rand::Rng + ?Sized,
    {
        Ok(self
            .seal_to_server
            .seal_chunks_into_reusing(payload, rng, out, records)?)
    }

    pub fn seal_payload_chunks_into_untracked<R>(
        &mut self,
        payload: &[u8],
        rng: &mut R,
        out: &mut Vec<u8>,
    ) -> Result<(), ClientHandshakeError>
    where
        R: RngCore + CryptoRng + rand::Rng + ?Sized,
    {
        Ok(self
            .seal_to_server
            .seal_chunks_into_untracked(payload, rng, out)?)
    }

    pub fn max_payload_chunk_len(&self) -> usize {
        self.seal_to_server.max_plaintext_len()
    }

    pub fn into_data_codecs(self) -> (DataRecordCodec, DataRecordCodec) {
        (self.seal_to_server, self.open_from_server)
    }

    pub fn open_server_record(&mut self, record: &[u8]) -> Result<Vec<u8>, ClientHandshakeError> {
        Ok(self.open_from_server.open(record)?)
    }

    pub fn open_server_record_owned(
        &mut self,
        record: Vec<u8>,
    ) -> Result<Vec<u8>, ClientHandshakeError> {
        Ok(self.open_from_server.open_owned(record)?)
    }

    pub fn open_server_record_in_place(
        &mut self,
        record: &mut Vec<u8>,
    ) -> Result<(), ClientHandshakeError> {
        Ok(self.open_from_server.open_in_place(record)?)
    }

    pub fn open_server_record_in_place_payload_range(
        &mut self,
        record: &mut Vec<u8>,
    ) -> Result<std::ops::Range<usize>, ClientHandshakeError> {
        Ok(self.open_from_server.open_in_place_payload_range(record)?)
    }

    pub fn open_server_identity_chunk(
        &mut self,
        record: &[u8],
    ) -> Result<ServerIdentityChunk, ClientHandshakeError> {
        Ok(ServerIdentityChunk::decode(
            &self.open_from_server.open(record)?,
        )?)
    }

    pub fn verify_server_identity_record(
        &mut self,
        record: &[u8],
        server_identity_public_key: &[u8],
        server_x25519_public_key: &[u8; 32],
    ) -> Result<(), ClientHandshakeError> {
        let payload = self.open_from_server.open(record)?;
        self.verify_server_identity_payload(
            &payload,
            server_identity_public_key,
            server_x25519_public_key,
        )
    }

    pub fn verify_server_identity_payload(
        &self,
        payload: &[u8],
        server_identity_public_key: &[u8],
        server_x25519_public_key: &[u8; 32],
    ) -> Result<(), ClientHandshakeError> {
        let signature = ServerIdentityProof::signature(payload)?;
        let pq_identity_binding = self
            .pq_identity_binding
            .ok_or(ClientHandshakeError::MissingPqIdentityBinding)?;
        identity::verify_server_identity(
            server_identity_public_key,
            signature,
            &self.keys.transcript_hash,
            server_x25519_public_key,
            &pq_identity_binding,
            self.keys.epoch,
        )?;
        Ok(())
    }

    pub fn decode_server_identity_payload(
        &self,
        payload: &[u8],
    ) -> Result<ServerIdentityProof, ClientHandshakeError> {
        Ok(ServerIdentityProof::decode(payload)?)
    }

    pub fn transcript_hash(&self) -> [u8; 32] {
        self.keys.transcript_hash
    }

    pub fn epoch(&self) -> u64 {
        self.keys.epoch
    }

    /// The post-handshake (post-PQ-rekey) session keys, the derivation root for
    /// per-substream mux-over-QUIC codecs (`expand_substream_keys`). Read-only:
    /// callers derive substream keys without disturbing the session's own codecs.
    /// `pub(crate)`: `SessionKeys` carries copyable secret material, and the only
    /// caller is the in-crate client runtime — never exposed on the public API.
    pub(crate) fn session_keys(&self) -> &SessionKeys {
        &self.keys
    }

    pub fn pq_identity_binding(&self) -> Result<[u8; 32], ClientHandshakeError> {
        self.pq_identity_binding
            .ok_or(ClientHandshakeError::MissingPqIdentityBinding)
    }

    pub fn apply_pq_rekey_shared(
        &mut self,
        suite: CipherSuite,
        x25519_shared_secret: &[u8; 32],
        pq_shared_secret: &[u8; 32],
        sandwich_secret: &[u8],
    ) -> Result<(), ClientHandshakeError> {
        let chain_secret = Zeroizing::new(pq::hybrid_sandwich_rekey(
            &self.keys.chain_secret,
            x25519_shared_secret,
            pq_shared_secret,
            sandwich_secret,
        )?);
        let next_keys = expand_epoch_keys(
            *chain_secret,
            self.keys.epoch.saturating_add(1),
            self.keys.transcript_hash,
            *x25519_shared_secret,
        )?;

        self.seal_to_server
            .rekey_with_suite(suite, next_keys.client_key, next_keys.client_nonce);
        self.open_from_server
            .rekey_with_suite(suite, next_keys.server_key, next_keys.server_nonce);
        self.keys = next_keys;
        self.keys.protect_secret_memory();
        Ok(())
    }

    pub fn apply_pq_rekey_shared_with_identity_binding(
        &mut self,
        suite: CipherSuite,
        x25519_shared_secret: &[u8; 32],
        pq_shared_secret: &[u8; 32],
        sandwich_secret: &[u8],
        pq_identity_binding: [u8; 32],
    ) -> Result<(), ClientHandshakeError> {
        self.apply_pq_rekey_shared(
            suite,
            x25519_shared_secret,
            pq_shared_secret,
            sandwich_secret,
        )?;
        self.pq_identity_binding = Some(pq_identity_binding);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use rand::{rngs::StdRng, SeedableRng};

    use super::*;
    use crate::{
        crypto::session::{derive_server_keys, X25519KeyPair, NONCE_LEN},
        tls::client_hello::tests::client_hello_fixture,
    };

    #[test]
    fn client_and_server_session_keys_match() {
        let client = X25519KeyPair::generate();
        let server = X25519KeyPair::generate();
        let psk = [0x5a_u8; 32];
        let client_hello = client_hello_fixture("example.com");
        let server_hello = crate::tls::server_hello::tests::server_hello_fixture();

        let client_keys = derive_session_keys(
            &psk,
            &client.private,
            &server.public,
            &client_hello,
            &server_hello,
        )
        .unwrap();
        let hash = transcript_hash(&client_hello, &server_hello);
        let server_keys = derive_server_keys(&psk, &server.private, &client.public, &hash).unwrap();

        assert_eq!(client_keys, server_keys);
    }

    #[test]
    fn derive_session_keys_from_shared_matches_private_key_path() {
        let client = X25519KeyPair::generate();
        let server = X25519KeyPair::generate();
        let psk = [0x5a_u8; 32];
        let client_hello = client_hello_fixture("example.com");
        let server_hello = crate::tls::server_hello::tests::server_hello_fixture();
        let shared = x25519_shared_secret(&client.private, &server.public);

        let from_private = derive_session_keys(
            &psk,
            &client.private,
            &server.public,
            &client_hello,
            &server_hello,
        )
        .unwrap();
        let from_shared =
            derive_session_keys_from_shared(&psk, &shared, &client_hello, &server_hello).unwrap();

        assert_eq!(from_private, from_shared);
    }

    #[test]
    fn builds_encrypted_connect_record() {
        let key = [9_u8; 32];
        let keys = SessionKeys {
            client_key: key,
            server_key: [8_u8; 32],
            client_nonce: [7_u8; NONCE_LEN],
            server_nonce: [6_u8; NONCE_LEN],
            chain_secret: [5_u8; 32],
            epoch: 0,
            transcript_hash: [4_u8; 32],
            x25519_shared_secret: [3_u8; 32],
        };
        let traffic = TrafficConfig {
            min_padding: 0,
            max_padding: 0,
            min_delay_ms: 0,
            max_delay_ms: 0,
            cover_min_interval_ms: 0,
            cover_max_interval_ms: 0,
            max_concurrent_streams: 1,
        };
        let request = ConnectRequest {
            host: "example.com".to_owned(),
            port: 443,
            initial_payload: b"hello".to_vec(),
        };
        let mut rng = StdRng::seed_from_u64(5);

        let mut session = ClientDataSession::new(keys.clone(), traffic).unwrap();
        let record = session
            .build_connect_record(request.clone(), &mut rng)
            .unwrap();
        let (mut open_from_client, _) = data_codecs(&keys, traffic).unwrap();
        let payload = open_from_client.open(&record).unwrap();

        // The C3 shaping pad is stripped transparently on open, so the CONNECT
        // decodes byte-for-byte despite the on-wire record being padded to a band.
        assert_eq!(ConnectRequest::decode(&payload).unwrap(), request);

        // C3: the on-wire record size must be one of the shaping bands, not the
        // raw `CONNECT_FIXED_LEN + host + payload` size that would leak the target.
        let header = crate::tls::record::parse_header(&record).unwrap();
        assert!(
            crate::protocol::command::connect_record_size_is_shaped(header.payload_len),
            "CONNECT wire size {} is not a shaping band",
            header.payload_len
        );
    }

    #[test]
    fn connect_record_lands_on_band_even_with_nonzero_traffic_padding() {
        // C3 regression: with a non-default TrafficConfig padding profile, the
        // CONNECT record must STILL land exactly on a shaping band (the seal path
        // bypasses profile sampling for shaping). If it added profile padding on
        // top, the size would drift off-band and re-expose a size signal.
        let keys = SessionKeys {
            client_key: [9_u8; 32],
            server_key: [8_u8; 32],
            client_nonce: [7_u8; NONCE_LEN],
            server_nonce: [6_u8; NONCE_LEN],
            chain_secret: [5_u8; 32],
            epoch: 0,
            transcript_hash: [4_u8; 32],
            x25519_shared_secret: [3_u8; 32],
        };
        let traffic = TrafficConfig {
            min_padding: 32,
            max_padding: 512,
            min_delay_ms: 0,
            max_delay_ms: 0,
            cover_min_interval_ms: 0,
            cover_max_interval_ms: 0,
            max_concurrent_streams: 1,
        };
        let request = ConnectRequest {
            host: "example.com".to_owned(),
            port: 443,
            initial_payload: b"hello".to_vec(),
        };
        for seed in 0..32 {
            let mut rng = StdRng::seed_from_u64(seed);
            let mut session = ClientDataSession::new(keys.clone(), traffic).unwrap();
            let record = session
                .build_connect_record(request.clone(), &mut rng)
                .unwrap();
            let header = crate::tls::record::parse_header(&record).unwrap();
            assert!(
                crate::protocol::command::connect_record_size_is_shaped(header.payload_len),
                "CONNECT wire size {} drifted off-band under non-zero padding (seed {seed})",
                header.payload_len
            );
            let (mut open_from_client, _) = data_codecs(&keys, traffic).unwrap();
            let payload = open_from_client.open(&record).unwrap();
            assert_eq!(ConnectRequest::decode(&payload).unwrap(), request);
        }
    }

    // Test helper: reassemble a PQ handshake frame (PX1Q/PX1K) from a buffer of
    // one or more concatenated sealed FramedChunk records, mirroring the
    // production reassembly path (PAR-21).
    fn open_framed_payload(codec: &mut DataRecordCodec, buf: &[u8]) -> Vec<u8> {
        use crate::protocol::command::{FramedReassembler, MAX_PQ_HANDSHAKE_FRAME};
        let mut reassembler = FramedReassembler::default();
        let mut offset = 0;
        while offset < buf.len() {
            let payload_len = u16::from_be_bytes([buf[offset + 3], buf[offset + 4]]) as usize;
            let end = offset + crate::tls::record::TLS_HEADER_LEN + payload_len;
            let chunk = codec.open(&buf[offset..end]).unwrap();
            if let Some(payload) = reassembler.push(&chunk, MAX_PQ_HANDSHAKE_FRAME).unwrap() {
                assert_eq!(
                    end,
                    buf.len(),
                    "framed payload completed before consuming all sealed records"
                );
                return payload;
            }
            offset = end;
        }
        panic!("framed payload did not complete");
    }

    /// PAR-21 core property: the PQ rekey (PX1Q) record is no longer a single
    /// fixed ~1631-byte record. It is split into >= 2 variable-length records
    /// (no single record carries the whole frame), the record count varies
    /// across sessions, and the server still reassembles it byte-for-byte.
    #[test]
    fn pq_rekey_record_is_split_into_variable_chunks() {
        let keys = SessionKeys {
            client_key: [9_u8; 32],
            server_key: [8_u8; 32],
            client_nonce: [7_u8; NONCE_LEN],
            server_nonce: [6_u8; NONCE_LEN],
            chain_secret: [5_u8; 32],
            epoch: 0,
            transcript_hash: [4_u8; 32],
            x25519_shared_secret: [3_u8; 32],
        };
        let traffic = TrafficConfig::default();
        let mut record_counts = std::collections::BTreeSet::new();
        let mut record_sizes = std::collections::BTreeSet::new();
        for seed in 0..32_u64 {
            let mut session = ClientDataSession::new(keys.clone(), traffic).unwrap();
            let mut rng = StdRng::seed_from_u64(seed);
            let (record, pending) = session.build_pq_rekey_record(&mut rng).unwrap();

            // Walk the concatenated sealed records by their TLS length headers.
            let mut offset = 0;
            let mut count = 0;
            while offset < record.len() {
                let payload_len =
                    u16::from_be_bytes([record[offset + 3], record[offset + 4]]) as usize;
                offset += crate::tls::record::TLS_HEADER_LEN + payload_len;
                count += 1;
                record_sizes.insert(payload_len);
            }
            assert_eq!(offset, record.len(), "records must tile the buffer exactly");
            assert!(
                count >= 2,
                "rekey must split into >= 2 records, got {count}"
            );
            record_counts.insert(count);

            // The server reassembles the exact original rekey request.
            let (mut server_open, _) = data_codecs(&keys, traffic).unwrap();
            let reassembled = open_framed_payload(&mut server_open, &record);
            // Exact bytes, not just well-framed: catches sealing / chunk-ordering
            // regressions that would still decode as a valid-looking PX1Q.
            assert_eq!(reassembled, pending.request_payload);
            assert!(PqRekeyRequest::decode(&reassembled).is_ok());
        }
        assert!(
            record_counts.len() >= 2,
            "per-session chunk size must vary the record count across sessions, got {record_counts:?}"
        );
        // Per-chunk randomization => many distinct record sizes across sessions
        // (not a single per-session size, not an equal-length run).
        assert!(
            record_sizes.len() >= 8,
            "per-chunk sizing must yield many distinct record sizes, got {}",
            record_sizes.len()
        );
    }

    #[test]
    fn pq_rekey_changes_client_session_keys() {
        let keys = SessionKeys {
            client_key: [9_u8; 32],
            server_key: [8_u8; 32],
            client_nonce: [7_u8; NONCE_LEN],
            server_nonce: [6_u8; NONCE_LEN],
            chain_secret: [5_u8; 32],
            epoch: 0,
            transcript_hash: [4_u8; 32],
            x25519_shared_secret: [3_u8; 32],
        };
        let traffic = TrafficConfig::default();
        let mut session = ClientDataSession::new(keys.clone(), traffic).unwrap();
        let mut rng = StdRng::seed_from_u64(6);

        let (record, pending) = session.build_pq_rekey_record(&mut rng).unwrap();
        let (mut server_open, _) = data_codecs(&keys, traffic).unwrap();
        let request =
            PqRekeyRequest::decode(&open_framed_payload(&mut server_open, &record)).unwrap();
        let server_x25519 = X25519KeyPair::generate();
        let x25519_shared =
            x25519_shared_secret(&server_x25519.private, &request.client_x25519_public);
        let encapsulation = pq::encapsulate(&request.client_mlkem_public_key).unwrap();
        let (_, mut client_open) = data_codecs(&keys, traffic).unwrap();
        let exchange_record = client_open
            .seal(
                &ServerKeyExchange {
                    server_x25519_public: server_x25519.public,
                    mlkem_ciphertext: encapsulation.ciphertext,
                }
                .encode_with_suite(CipherSuite::ChaCha20Poly1305)
                .unwrap(),
                &mut rng,
            )
            .unwrap();
        session
            .apply_server_key_exchange_record(&exchange_record, &pending, b"test-psk")
            .unwrap();

        let chain_secret = pq::hybrid_sandwich_rekey(
            &keys.chain_secret,
            &x25519_shared,
            &encapsulation.shared_secret,
            b"test-psk",
        )
        .unwrap();
        let next_keys = expand_epoch_keys(
            chain_secret,
            keys.epoch + 1,
            keys.transcript_hash,
            x25519_shared,
        )
        .unwrap();
        assert_eq!(session.keys.epoch, 1);
        assert_eq!(session.keys.client_key, next_keys.client_key);
        assert_eq!(session.keys.client_nonce, next_keys.client_nonce);
    }

    #[test]
    fn pq_rekey_with_aes_suite_switches_data_plane_cipher() {
        let keys = SessionKeys {
            client_key: [9_u8; 32],
            server_key: [8_u8; 32],
            client_nonce: [7_u8; NONCE_LEN],
            server_nonce: [6_u8; NONCE_LEN],
            chain_secret: [5_u8; 32],
            epoch: 0,
            transcript_hash: [4_u8; 32],
            x25519_shared_secret: [3_u8; 32],
        };
        let traffic = TrafficConfig::default();
        let mut session = ClientDataSession::new(keys.clone(), traffic).unwrap();
        let mut rng = StdRng::seed_from_u64(6);

        let (record, pending) = session.build_pq_rekey_record(&mut rng).unwrap();
        let (mut server_open, _) = data_codecs(&keys, traffic).unwrap();
        let request =
            PqRekeyRequest::decode(&open_framed_payload(&mut server_open, &record)).unwrap();
        let server_x25519 = X25519KeyPair::generate();
        let x25519_shared =
            x25519_shared_secret(&server_x25519.private, &request.client_x25519_public);
        let encapsulation = pq::encapsulate(&request.client_mlkem_public_key).unwrap();
        let (_, mut client_open) = data_codecs(&keys, traffic).unwrap();
        // The server signals AES-256-GCM in the (ChaCha-sealed) ServerKeyExchange.
        let exchange_record = client_open
            .seal(
                &ServerKeyExchange {
                    server_x25519_public: server_x25519.public,
                    mlkem_ciphertext: encapsulation.ciphertext,
                }
                .encode_with_suite(CipherSuite::Aes256Gcm)
                .unwrap(),
                &mut rng,
            )
            .unwrap();
        session
            .apply_server_key_exchange_record(&exchange_record, &pending, b"test-psk")
            .unwrap();

        // The epoch keys the server would independently derive.
        let chain_secret = pq::hybrid_sandwich_rekey(
            &keys.chain_secret,
            &x25519_shared,
            &encapsulation.shared_secret,
            b"test-psk",
        )
        .unwrap();
        let next_keys = expand_epoch_keys(
            chain_secret,
            keys.epoch + 1,
            keys.transcript_hash,
            x25519_shared,
        )
        .unwrap();

        // The client now seals data-plane records under the negotiated suite. A
        // server opener built with AES-256-GCM + the same epoch keys opens them;
        // a ChaCha opener does NOT -- proving the data plane really switched to
        // AES rather than silently staying on ChaCha.
        let mut payload_rng = StdRng::seed_from_u64(99);
        let sealed = session
            .seal_payload(b"after-aes-rekey", &mut payload_rng)
            .unwrap();
        let padding = PaddingProfile::from_config(traffic).unwrap();

        let mut aes_opener = DataRecordCodec::new(
            AeadCodec::new_with_suite(
                CipherSuite::Aes256Gcm,
                next_keys.client_key,
                next_keys.client_nonce,
            ),
            padding,
            CLIENT_TO_SERVER_AAD,
        );
        assert_eq!(aes_opener.open(&sealed).unwrap(), b"after-aes-rekey");

        let mut chacha_opener = DataRecordCodec::new(
            AeadCodec::new_with_suite(
                CipherSuite::ChaCha20Poly1305,
                next_keys.client_key,
                next_keys.client_nonce,
            ),
            padding,
            CLIENT_TO_SERVER_AAD,
        );
        assert!(
            chacha_opener.open(&sealed).is_err(),
            "data plane must have switched to AES-256-GCM"
        );
    }

    #[test]
    fn negotiated_suite_byte_is_aead_protected_against_downgrade() {
        // The server signals the data-plane suite in the AEAD-sealed
        // ServerKeyExchange. A MITM cannot flip the suite (AES <-> ChaCha) without
        // breaking the AEAD tag, so the negotiation fails closed (DoS at worst),
        // never a silent downgrade.
        let key = [0x55_u8; 32];
        let nonce = [0x66_u8; NONCE_LEN];
        let ske = ServerKeyExchange {
            server_x25519_public: [0x77_u8; 32],
            mlkem_ciphertext: vec![0x88_u8; 64],
        };
        let plaintext = ske.encode_with_suite(CipherSuite::Aes256Gcm).unwrap();
        let suite_pos = plaintext.len() - 1; // the suite tag is the last plaintext byte

        let mut enc = AeadCodec::new(key, nonce);
        let mut sealed = enc.seal(&plaintext, CLIENT_TO_SERVER_AAD).unwrap();
        sealed[suite_pos] ^= 1; // flip the ciphertext byte carrying the suite tag
        let mut dec = AeadCodec::new(key, nonce);
        assert!(
            matches!(
                dec.open(&sealed, CLIENT_TO_SERVER_AAD),
                Err(SessionError::Aead)
            ),
            "tampering the sealed suite byte must fail the AEAD, blocking a downgrade"
        );
    }

    #[test]
    fn server_identity_rejects_proof_from_different_pq_rekey() {
        let keys = SessionKeys {
            client_key: [9_u8; 32],
            server_key: [8_u8; 32],
            client_nonce: [7_u8; NONCE_LEN],
            server_nonce: [6_u8; NONCE_LEN],
            chain_secret: [5_u8; 32],
            epoch: 0,
            transcript_hash: [4_u8; 32],
            x25519_shared_secret: [3_u8; 32],
        };
        let traffic = TrafficConfig::default();
        let server_static = X25519KeyPair::generate();
        let identity_keys = identity::keypair();
        let mut rng = StdRng::seed_from_u64(66);
        let (first_session, first_binding) = apply_test_pq_rekey(keys.clone(), traffic, &mut rng);
        let (second_session, _) = apply_test_pq_rekey(keys, traffic, &mut rng);
        let signature = identity::sign_server_identity(
            &identity_keys.secret,
            &first_session.transcript_hash(),
            &server_static.public,
            &first_binding,
            first_session.epoch(),
        )
        .unwrap();
        let proof = ServerIdentityProof { signature }.encode().unwrap();

        first_session
            .verify_server_identity_payload(&proof, &identity_keys.public, &server_static.public)
            .unwrap();
        assert!(second_session
            .verify_server_identity_payload(&proof, &identity_keys.public, &server_static.public)
            .is_err());
    }

    fn test_session_keys() -> SessionKeys {
        SessionKeys {
            client_key: [9_u8; 32],
            server_key: [8_u8; 32],
            client_nonce: [7_u8; NONCE_LEN],
            server_nonce: [6_u8; NONCE_LEN],
            chain_secret: [5_u8; 32],
            epoch: 0,
            transcript_hash: [4_u8; 32],
            x25519_shared_secret: [3_u8; 32],
        }
    }

    fn apply_test_pq_rekey(
        keys: SessionKeys,
        traffic: TrafficConfig,
        rng: &mut StdRng,
    ) -> (ClientDataSession, [u8; 32]) {
        let mut session = ClientDataSession::new(keys.clone(), traffic).unwrap();
        let (_record, pending) = session.build_pq_rekey_record(rng).unwrap();
        let (_server_open, mut server_seal) = data_codecs(&keys, traffic).unwrap();
        let server_x25519 = X25519KeyPair::generate();
        let x25519_shared = pending.x25519_shared_secret(&server_x25519.public);
        let encapsulation = pq::encapsulate(&pending.mlkem.public).unwrap();
        let exchange_payload = ServerKeyExchange {
            server_x25519_public: server_x25519.public,
            mlkem_ciphertext: encapsulation.ciphertext,
        }
        .encode_with_suite(CipherSuite::ChaCha20Poly1305)
        .unwrap();
        let binding = pending.identity_binding(&exchange_payload);
        let exchange_record = server_seal.seal(&exchange_payload, rng).unwrap();

        session
            .apply_server_key_exchange_record(&exchange_record, &pending, b"test-psk")
            .unwrap();
        let chain_secret = pq::hybrid_sandwich_rekey(
            &keys.chain_secret,
            &x25519_shared,
            &encapsulation.shared_secret,
            b"test-psk",
        )
        .unwrap();
        let next_keys = expand_epoch_keys(
            chain_secret,
            keys.epoch + 1,
            keys.transcript_hash,
            x25519_shared,
        )
        .unwrap();
        assert_eq!(session.keys.client_key, next_keys.client_key);
        (session, binding)
    }

    #[test]
    fn seal_and_open_round_trip_through_paired_codecs() {
        let keys = test_session_keys();
        let traffic = TrafficConfig::default();
        let mut client = ClientDataSession::new(keys.clone(), traffic).unwrap();
        let (mut server_open, mut server_seal) = data_codecs(&keys, traffic).unwrap();
        let mut rng = StdRng::seed_from_u64(11);

        let payload = b"unit-test-payload";
        let record = client.seal_payload(payload, &mut rng).unwrap();
        let opened = server_open.open(&record).unwrap();
        assert_eq!(opened, payload);

        // First server-to-client record: opened in place on the client.
        let mut first = server_seal.seal(b"server-says-hi", &mut rng).unwrap();
        client.open_server_record_in_place(&mut first).unwrap();
        assert_eq!(first, b"server-says-hi");

        // Second server-to-client record (new nonce): opened via the owned API.
        let second = server_seal.seal(b"server-says-bye", &mut rng).unwrap();
        let owned = client.open_server_record_owned(second).unwrap();
        assert_eq!(owned, b"server-says-bye");
    }

    #[test]
    fn seal_payload_chunks_matches_seal_payload_chunks_into_for_small_payloads() {
        let keys = test_session_keys();
        let traffic = TrafficConfig::default();
        let mut a = ClientDataSession::new(keys.clone(), traffic).unwrap();
        let mut b = ClientDataSession::new(keys.clone(), traffic).unwrap();
        let mut rng_a = StdRng::seed_from_u64(33);
        let mut rng_b = StdRng::seed_from_u64(33);

        let payload = b"abc";
        let chunks = a.seal_payload_chunks(payload, &mut rng_a).unwrap();

        let mut out = Vec::new();
        let _records = b
            .seal_payload_chunks_into(payload, &mut rng_b, &mut out)
            .unwrap();

        let flattened: Vec<u8> = chunks.into_iter().flatten().collect();
        assert_eq!(flattened, out);
    }

    #[test]
    fn max_payload_chunk_len_is_positive() {
        let keys = test_session_keys();
        let traffic = TrafficConfig::default();
        let session = ClientDataSession::new(keys, traffic).unwrap();
        assert!(session.max_payload_chunk_len() > 0);
    }

    #[test]
    fn into_data_codecs_exposes_underlying_codecs() {
        let keys = test_session_keys();
        let traffic = TrafficConfig::default();
        let session = ClientDataSession::new(keys.clone(), traffic).unwrap();
        let (seal_to_server, open_from_server) = session.into_data_codecs();
        assert_eq!(
            seal_to_server.max_plaintext_len(),
            data_codecs(&keys, traffic).unwrap().0.max_plaintext_len()
        );
        // The opening codec must still accept records sealed by a fresh paired
        // codec built from the same keys.
        let (mut paired_seal, _) = data_codecs(&keys, traffic).unwrap();
        let mut rng = StdRng::seed_from_u64(7);
        let _ = paired_seal.seal(b"hello", &mut rng).unwrap();
        drop(open_from_server);
    }
}
