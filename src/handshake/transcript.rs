use sha2::{Digest, Sha256};

pub type TranscriptHash = [u8; 32];

/// Bind the ClientHello and ServerHello records into the handshake transcript hash
/// that seeds the session keys and is covered by the server identity signature.
///
/// Each record is length-prefixed with its big-endian `u32` byte length so the
/// CH/SH boundary is canonically bound by the hash. Without the prefix the inputs
/// are merely concatenated, and any `(CH, SH) != (CH', SH')` whose byte
/// concatenations are equal (e.g. trailing CH bytes lumped into SH on one side)
/// would collide to the same transcript — and thus the same keys / signed digest —
/// for two semantically different handshakes. The records are always well under
/// `u32::MAX`, so the cast never truncates. The label is versioned: this is the
/// v2 framing, distinct on the wire from the previous prefix-less v1, so a peer on
/// the old framing fails key agreement (fail-closed) rather than interoperating
/// under an ambiguous transcript — matched binaries on both ends adopt it together.
pub fn transcript_hash(client_hello_record: &[u8], server_hello_record: &[u8]) -> TranscriptHash {
    let mut hasher = Sha256::new();
    hasher.update(b"ParallaX v2 handshake transcript");
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

    /// The CH/SH boundary must be canonically bound: two distinct (CH, SH) pairs
    /// whose raw concatenations are byte-identical MUST hash differently. Before the
    /// length prefix, `("xy", "z")` and `("x", "yz")` both hashed `prefix || "xyz"`
    /// and collided; the prefix makes the split unambiguous.
    #[test]
    fn transcript_hash_is_unambiguous_across_the_split() {
        let split_a = transcript_hash(b"xy", b"z");
        let split_b = transcript_hash(b"x", b"yz");
        assert_ne!(
            split_a, split_b,
            "the CH/SH boundary must be bound by the hash, not just the concatenation"
        );

        // A boundary shift by one byte in both directions also stays distinct.
        let c = transcript_hash(b"clienthello", b"serverhello");
        let d = transcript_hash(b"clienthellos", b"erverhello");
        assert_ne!(c, d, "shifting the split point must change the transcript");
    }
}
