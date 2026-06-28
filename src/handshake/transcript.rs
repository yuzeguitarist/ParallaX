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
}
