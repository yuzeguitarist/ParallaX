use sha2::{Digest, Sha256};

pub type TranscriptHash = [u8; 32];

pub fn transcript_hash(client_hello_record: &[u8], server_hello_record: &[u8]) -> TranscriptHash {
    let mut hasher = Sha256::new();
    hasher.update(b"ParallaX v1 handshake transcript");
    // Length-prefix each variable-length record (32-bit big-endian, matching the
    // crate's other hash inputs, e.g. `crypto::identity`). Without it the split
    // point between the two concatenated records is not bound by the hash, so
    // distinct (client_hello, server_hello) pairs whose concatenations coincide
    // would collide. The current callers pass whole self-delimiting TLS records,
    // so this is defense in depth, but it makes the canonicalization explicit and
    // consistent with the rest of the library (this hash derives session keys and
    // is covered by the server's identity signature).
    hasher.update((client_hello_record.len() as u32).to_be_bytes());
    hasher.update(client_hello_record);
    hasher.update((server_hello_record.len() as u32).to_be_bytes());
    hasher.update(server_hello_record);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transcript_hash_binds_client_and_server_hello() {
        let a = transcript_hash(b"client-hello-a", b"server-hello-a");
        let b = transcript_hash(b"client-hello-b", b"server-hello-a");
        let c = transcript_hash(b"client-hello-a", b"server-hello-b");

        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.len(), 32);
    }

    #[test]
    fn transcript_hash_binds_the_record_boundary() {
        // The split point between the two records must be bound by the hash:
        // ("ab","c") and ("a","bc") share the same concatenation but must hash
        // differently, which the length prefixes guarantee.
        assert_ne!(
            transcript_hash(b"ab", b"c"),
            transcript_hash(b"a", b"bc"),
            "the client/server boundary must be canonicalized"
        );
    }

    #[test]
    fn hrr_and_final_server_hello_produce_incompatible_epoch_zero_keys() {
        use crate::{
            crypto::session::{derive_server_keys_from_shared, AeadCodec, SessionError},
            handshake::client::derive_session_keys_from_shared,
            protocol::data::CLIENT_TO_SERVER_AAD,
            tls::{client_hello::tests::client_hello_fixture, server_hello},
        };

        let client_hello = client_hello_fixture("example.com");
        let final_server_hello = server_hello::tests::server_hello_fixture();
        // TLS 1.3 HRR selecting secp256r1, with the fixture's echoed session ID.
        let mut hrr = vec![
            0x16, 0x03, 0x03, 0x00, 0x58, 0x02, 0x00, 0x00, 0x54, 0x03, 0x03,
        ];
        hrr.extend_from_slice(&[
            0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65,
            0xb8, 0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2,
            0xc8, 0xa8, 0x33, 0x9c,
        ]);
        hrr.push(32);
        hrr.extend_from_slice(&[0x55; 32]);
        hrr.extend_from_slice(&[
            0x13, 0x01, 0x00, 0x00, 0x0c, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04, 0x00, 0x33, 0x00,
            0x02, 0x00, 0x17,
        ]);
        // The server's first-response parser accepts HRR as a TLS 1.3 ServerHello.
        assert!(
            server_hello::parse_server_hello(&hrr)
                .unwrap()
                .tls13_selected
        );

        let psk = [0x5a; 32];
        let shared = [0x42; 32];
        let server_context = transcript_hash(&client_hello, &hrr);
        let server_keys = derive_server_keys_from_shared(&psk, &shared, &server_context).unwrap();
        let client_keys =
            derive_session_keys_from_shared(&psk, &shared, &client_hello, &final_server_hello)
                .unwrap();
        assert_eq!(server_keys.epoch, 0);
        assert_eq!(client_keys.epoch, 0);
        assert_ne!(server_keys.transcript_hash, client_keys.transcript_hash);
        assert_ne!(server_keys.client_key, client_keys.client_key);

        let mut seal = AeadCodec::new(client_keys.client_key, client_keys.client_nonce);
        let ciphertext = seal.seal(b"PX1Q", CLIENT_TO_SERVER_AAD).unwrap();
        let mut open = AeadCodec::new(server_keys.client_key, server_keys.client_nonce);
        assert!(matches!(
            open.open(&ciphertext, CLIENT_TO_SERVER_AAD),
            Err(SessionError::Aead)
        ));
    }
}
