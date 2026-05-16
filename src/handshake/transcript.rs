use sha2::{Digest, Sha256};

pub type TranscriptHash = [u8; 32];

pub fn transcript_hash(client_hello_record: &[u8], server_hello_record: &[u8]) -> TranscriptHash {
    let mut hasher = Sha256::new();
    hasher.update(b"ParallaX v1 handshake transcript");
    hasher.update(client_hello_record);
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
}
