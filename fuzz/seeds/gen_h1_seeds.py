#!/usr/bin/env python3
"""Generate the H1 (zlib decompression bomb) seed corpus for the
tls_compressed_cert fuzz target.

Each seed is a CompressedCertificate *body* — exactly what the target's
fuzz::parse_compressed_certificate_body receives, all big-endian:

    [u16 algorithm=0x0001=zlib][u24 uncompressed_len][u24 compressed_len][zlib stream]

Random bytes can't pass the zlib-validity gate, so these hand-built seeds are
required to drive H1. Run from anywhere:  python3 fuzz/seeds/gen_h1_seeds.py
"""
import os
import zlib

OUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tls_compressed_cert")


def body(uncompressed_len: int, stream: bytes) -> bytes:
    b = bytearray()
    b += (0x0001).to_bytes(2, "big")            # algorithm = zlib (CERT_COMPRESSION_ZLIB)
    b += (uncompressed_len).to_bytes(3, "big")  # u24 declared uncompressed length
    b += (len(stream)).to_bytes(3, "big")       # u24 compressed length (must match exactly)
    b += stream
    return bytes(b)


def write(buf: bytes, name: str) -> None:
    path = os.path.join(OUT_DIR, name)
    with open(path, "wb") as f:
        f.write(buf)
    # Self-check the wire invariant the parser relies on.
    assert buf[:2] == b"\x00\x01", name
    assert int.from_bytes(buf[5:8], "big") == len(buf) - 8, name
    print(f"wrote {path} ({len(buf)} bytes)")


def main() -> None:
    os.makedirs(OUT_DIR, exist_ok=True)

    # 1. Valid-gate seed (200 zero bytes): teaches the fuzzer the zlib framing so
    #    it can then mutate uncompressed_len upward toward the bomb.
    write(body(200, zlib.compress(b"\x00" * 200, 9)), "h1_zlib_valid.bin")

    # 2. with_capacity amplifier: u24-max declared length, tiny real stream.
    write(body(0xFFFFFF, zlib.compress(b"\x00" * 16, 9)), "seed_h1_withcapacity_16mib")

    # 3. The real bomb: a small valid zlib stream that inflates to ~3 GiB, so the
    #    uncapped read_to_end grows the Vec past any sane RSS cap. windowBits=15
    #    (zlib wrapper) — raw(-15)/gzip(+16) would be rejected by flate2.
    target = 3 * 1024 ** 3
    co = zlib.compressobj(9, zlib.DEFLATED, 15)
    chunk = b"\x00" * (8 * 1024 * 1024)
    stream = bytearray()
    for _ in range(target // len(chunk)):
        stream += co.compress(chunk)
    stream += co.flush()
    write(body(0xFFFFFF, bytes(stream)), "seed_h1_zlib_bomb_3gib")


if __name__ == "__main__":
    main()
