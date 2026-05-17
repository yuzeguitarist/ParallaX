use rand::{CryptoRng, RngCore};
use thiserror::Error;

use crate::{
    config::TrafficConfig,
    crypto::{
        identity::{self, IdentityError},
        pq::{self, PqError},
        session::{
            derive_client_keys, expand_epoch_keys, x25519_shared_secret, AeadCodec, SessionError,
            SessionKeys, X25519KeyPair,
        },
    },
    protocol::{
        command::{
            ConnectRequest, ConnectRequestError, PqRekeyError, PqRekeyRequest, ServerIdentityChunk,
            ServerIdentityChunkError, ServerIdentityProof, ServerIdentityProofError,
            ServerKeyExchange, ServerKeyExchangeError,
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
    #[error("server key exchange command error: {0}")]
    ServerKeyExchange(#[from] ServerKeyExchangeError),
    #[error("server identity proof command error: {0}")]
    ServerIdentityProof(#[from] ServerIdentityProofError),
    #[error("server identity chunk command error: {0}")]
    ServerIdentityChunk(#[from] ServerIdentityChunkError),
    #[error("server identity verification failed: {0}")]
    Identity(#[from] IdentityError),
}

pub fn derive_session_keys(
    client_private: &[u8; 32],
    server_public: &[u8; 32],
    client_hello_record: &[u8],
    server_hello_record: &[u8],
) -> Result<SessionKeys, ClientHandshakeError> {
    let transcript_hash = transcript_hash(client_hello_record, server_hello_record);
    Ok(derive_client_keys(
        client_private,
        server_public,
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
}

pub struct PendingPqRekey {
    x25519: X25519KeyPair,
    mlkem: pq::MlKemKeyPair,
}

impl PendingPqRekey {
    pub fn x25519_shared_secret(&self, server_public: &[u8; 32]) -> [u8; 32] {
        x25519_shared_secret(&self.x25519.private, server_public)
    }

    pub fn mlkem_secret_key(&self) -> &[u8] {
        &self.mlkem.secret
    }
}

impl ClientDataSession {
    pub fn new(keys: SessionKeys, traffic: TrafficConfig) -> Result<Self, ClientHandshakeError> {
        let (seal_to_server, open_from_server) = data_codecs(&keys, traffic)?;
        Ok(Self {
            seal_to_server,
            open_from_server,
            keys,
        })
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
        let request = PqRekeyRequest {
            client_x25519_public: x25519.public,
            client_mlkem_public_key: mlkem.public.clone(),
        };
        let record = self.seal_to_server.seal(&request.encode()?, rng)?;
        Ok((record, PendingPqRekey { x25519, mlkem }))
    }

    pub fn apply_server_key_exchange_record(
        &mut self,
        record: &[u8],
        pending: &PendingPqRekey,
        sandwich_secret: &[u8],
    ) -> Result<(), ClientHandshakeError> {
        let exchange = self.open_server_key_exchange_record(record)?;
        let x25519_shared = pending.x25519_shared_secret(&exchange.server_x25519_public);
        let pq_shared = pq::decapsulate(&exchange.mlkem_ciphertext, &pending.mlkem.secret)?;
        self.apply_pq_rekey_shared(&x25519_shared, &pq_shared, sandwich_secret)?;
        Ok(())
    }

    pub fn open_server_key_exchange_record(
        &mut self,
        record: &[u8],
    ) -> Result<ServerKeyExchange, ClientHandshakeError> {
        let payload = self.open_from_server.open(record)?;
        Ok(ServerKeyExchange::decode(&payload)?)
    }

    pub fn build_connect_record<R>(
        &mut self,
        request: ConnectRequest,
        rng: &mut R,
    ) -> Result<Vec<u8>, ClientHandshakeError>
    where
        R: RngCore + CryptoRng + rand::Rng + ?Sized,
    {
        let payload = request.encode()?;
        Ok(self.seal_to_server.seal(&payload, rng)?)
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
        let proof = ServerIdentityProof::decode(payload)?;
        identity::verify_server_identity(
            server_identity_public_key,
            &proof.signature,
            &self.keys.transcript_hash,
            server_x25519_public_key,
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

    pub fn apply_pq_rekey_shared(
        &mut self,
        x25519_shared_secret: &[u8; 32],
        pq_shared_secret: &[u8; 32],
        sandwich_secret: &[u8],
    ) -> Result<(), ClientHandshakeError> {
        let chain_secret = pq::hybrid_sandwich_rekey(
            &self.keys.chain_secret,
            x25519_shared_secret,
            pq_shared_secret,
            sandwich_secret,
        )?;
        let next_keys = expand_epoch_keys(
            chain_secret,
            self.keys.epoch + 1,
            self.keys.transcript_hash,
            *x25519_shared_secret,
        )?;

        self.seal_to_server
            .rekey(next_keys.client_key, next_keys.client_nonce);
        self.open_from_server
            .rekey(next_keys.server_key, next_keys.server_nonce);
        self.keys = next_keys;
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
        let client_hello = client_hello_fixture("example.com");
        let server_hello = crate::tls::server_hello::tests::server_hello_fixture();

        let client_keys = derive_session_keys(
            &client.private,
            &server.public,
            &client_hello,
            &server_hello,
        )
        .unwrap();
        let hash = transcript_hash(&client_hello, &server_hello);
        let server_keys = derive_server_keys(&server.private, &client.public, &hash).unwrap();

        assert_eq!(client_keys, server_keys);
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

        assert_eq!(ConnectRequest::decode(&payload).unwrap(), request);
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
        let request = PqRekeyRequest::decode(&server_open.open(&record).unwrap()).unwrap();
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
                .encode()
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
}
