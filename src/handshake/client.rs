use rand::{CryptoRng, RngCore};
use thiserror::Error;

use crate::{
    config::TrafficConfig,
    crypto::{
        pq::{self, PqError},
        session::{derive_client_keys, AeadCodec, SessionError, SessionKeys},
    },
    protocol::{
        command::{ConnectRequest, ConnectRequestError, PqRekeyError, PqRekeyRequest},
        data::{DataRecordCodec, DataRecordError, CLIENT_TO_SERVER_AAD, SERVER_TO_CLIENT_AAD},
    },
    traffic::{PaddingProfile, TrafficError},
};

use super::transcript::session_context;

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
}

pub fn derive_session_keys(
    client_private: &[u8; 32],
    server_public: &[u8; 32],
    client_hello_record: &[u8],
    server_random: &[u8; 32],
) -> Result<SessionKeys, ClientHandshakeError> {
    let context = session_context(client_hello_record, server_random);
    Ok(derive_client_keys(client_private, server_public, &context)?)
}

pub fn data_codecs(
    keys: SessionKeys,
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

impl ClientDataSession {
    pub fn new(keys: SessionKeys, traffic: TrafficConfig) -> Result<Self, ClientHandshakeError> {
        let (seal_to_server, open_from_server) = data_codecs(keys, traffic)?;
        Ok(Self {
            seal_to_server,
            open_from_server,
            keys,
        })
    }

    pub fn build_pq_rekey_record<R>(
        &mut self,
        server_pq_public_key: &[u8],
        rng: &mut R,
    ) -> Result<Vec<u8>, ClientHandshakeError>
    where
        R: RngCore + CryptoRng + rand::Rng + ?Sized,
    {
        let encapsulation = pq::encapsulate(server_pq_public_key)?;
        let request = PqRekeyRequest {
            ciphertext: encapsulation.ciphertext,
        };
        let record = self.seal_to_server.seal(&request.encode()?, rng)?;
        self.apply_pq_rekey(&encapsulation.shared_secret)?;
        Ok(record)
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

    pub fn open_server_record(&mut self, record: &[u8]) -> Result<Vec<u8>, ClientHandshakeError> {
        Ok(self.open_from_server.open(record)?)
    }

    fn apply_pq_rekey(&mut self, shared_secret: &[u8; 32]) -> Result<(), ClientHandshakeError> {
        let (client_key, client_nonce) = pq::hybrid_rekey(
            &self.keys.client_key,
            &self.keys.client_nonce,
            shared_secret,
            b"client",
        )?;
        let (server_key, server_nonce) = pq::hybrid_rekey(
            &self.keys.server_key,
            &self.keys.server_nonce,
            shared_secret,
            b"server",
        )?;

        self.seal_to_server.rekey(client_key, client_nonce);
        self.open_from_server.rekey(server_key, server_nonce);
        self.keys.client_key = client_key;
        self.keys.client_nonce = client_nonce;
        self.keys.server_key = server_key;
        self.keys.server_nonce = server_nonce;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use rand::{rngs::StdRng, SeedableRng};

    use super::*;
    use crate::{
        crypto::session::{derive_server_keys, X25519KeyPair},
        tls::client_hello::tests::client_hello_fixture,
    };

    #[test]
    fn client_and_server_session_keys_match() {
        let client = X25519KeyPair::generate();
        let server = X25519KeyPair::generate();
        let client_hello = client_hello_fixture("example.com");
        let server_random = [3_u8; 32];

        let client_keys = derive_session_keys(
            &client.private,
            &server.public,
            &client_hello,
            &server_random,
        )
        .unwrap();
        let context = session_context(&client_hello, &server_random);
        let server_keys = derive_server_keys(&server.private, &client.public, &context).unwrap();

        assert_eq!(client_keys, server_keys);
    }

    #[test]
    fn builds_encrypted_connect_record() {
        let key = [9_u8; 32];
        let keys = SessionKeys {
            client_key: key,
            server_key: [8_u8; 32],
            client_nonce: [7_u8; 12],
            server_nonce: [6_u8; 12],
        };
        let traffic = TrafficConfig {
            min_padding: 0,
            max_padding: 0,
            min_delay_ms: 0,
            max_delay_ms: 0,
            max_concurrent_streams: 1,
        };
        let request = ConnectRequest {
            host: "example.com".to_owned(),
            port: 443,
            initial_payload: b"hello".to_vec(),
        };
        let mut rng = StdRng::seed_from_u64(5);

        let mut session = ClientDataSession::new(keys, traffic).unwrap();
        let record = session
            .build_connect_record(request.clone(), &mut rng)
            .unwrap();
        let (mut open_from_client, _) = data_codecs(keys, traffic).unwrap();
        let payload = open_from_client.open(&record).unwrap();

        assert_eq!(ConnectRequest::decode(&payload).unwrap(), request);
    }

    #[test]
    fn pq_rekey_changes_client_session_keys() {
        let pq_keys = pq::keypair();
        let keys = SessionKeys {
            client_key: [9_u8; 32],
            server_key: [8_u8; 32],
            client_nonce: [7_u8; 12],
            server_nonce: [6_u8; 12],
        };
        let traffic = TrafficConfig::default();
        let mut session = ClientDataSession::new(keys, traffic).unwrap();
        let mut rng = StdRng::seed_from_u64(6);

        let record = session
            .build_pq_rekey_record(&pq_keys.public, &mut rng)
            .unwrap();
        let (mut server_open, _) = data_codecs(keys, traffic).unwrap();
        let request = PqRekeyRequest::decode(&server_open.open(&record).unwrap()).unwrap();
        let shared = pq::decapsulate(&request.ciphertext, &pq_keys.secret).unwrap();

        let (client_key, client_nonce) =
            pq::hybrid_rekey(&keys.client_key, &keys.client_nonce, &shared, b"client").unwrap();
        assert_eq!(session.keys.client_key, client_key);
        assert_eq!(session.keys.client_nonce, client_nonce);
    }
}
