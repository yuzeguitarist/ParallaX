# Secret Store & Sealed Configs

> Navigation: [Index](README.md) | [Configuration Reference](Configuration-Reference.md) | [Systemd Service & Security Hardening](Systemd-Service-&-Security-Hardening.md)

## Purpose

ParallaX has exactly three secret config fields — `crypto.psk`,
`server.private_key`, and `server.identity_secret_key`. A secret reference can pull
them from a file, an environment variable, or a **machine-bound sealed bundle**.
`src/secret_store.rs` implements the sealed form: secrets are encrypted under a
host-local key so that a config file plus its sealed bundle are useless if copied
to any other machine. `plx seal` produces the bundle and rewrites the config to
reference it.

For the reference syntax (`{ sealed = "bundle.enc#field" }`) and how it composes
with the file/env forms, see the secret-source table in
[Configuration Reference](Configuration-Reference.md). This page documents the
mechanism and its threat model.

## Threat model

Sealing protects against **accidental config/bundle leakage only** — a pasted
config, a backup, a screenshare. The host keyfile is the root of trust; an attacker
who can read it (a root or kernel compromise) is explicitly out of scope. Sealing
turns "the config file is a credential" into "the config file is inert without this
specific machine's keyfile."

## How a secret is sealed

| Element | Detail |
|---|---|
| Host key | A 32-byte random key in a keyfile, default `/var/lib/parallax/host.key` (override with `$PARALLAX_HOST_KEY_FILE`). Must be `0600` and owned by the running user, exactly 32 bytes base64. |
| Per-secret KEK | `HKDF-SHA256(ikm = host_key, salt = random 32B, info = "parallax-seal-v1\|<field>")`. |
| Sealing AEAD | The base64 secret text is sealed with XChaCha20-Poly1305 (24-byte random nonce), AAD = `version ‖ bundle_id ‖ field`. |
| Bundle | TOML with a version (`1`), a random per-bundle id, and one sealed entry (`{salt, nonce, ciphertext}`) per field. |

The random **bundle id** is bound into every entry's AAD, so an entry cannot be
transplanted into a different bundle or rolled back to a stale one.

## Why HKDF salt vs IKM

The host key is the HKDF **input keying material**, and the per-secret salt is
random per entry, so two machines never derive the same KEK even for the same field
value. Each field gets a distinct `info` label, so the KEK for `psk` cannot decrypt
the `server.private_key` entry.

## Memory hygiene

Host-key bytes and resolved plaintext are held in `Zeroizing` wrappers and scrubbed
on drop; stack copies made during sealing/opening are explicitly zeroized. This
matches the zeroization discipline used across the crypto subsystems.

## API surface (`src/secret_store.rs`)

- `load_host_key(path)` / `create_host_key(path)` — load (with permission checks) or
  generate the host keyfile; `create_host_key` refuses to overwrite an existing one.
- `seal_all(host_key, secrets)` — seal `(field, base64_secret)` pairs into a
  `SealedBundle`.
- `read_bundle(path)` — deserialize a TOML sealed bundle.
- `open_sealed_reference(base, "path#field", overrides)` — resolve a `sealed`
  reference to its plaintext base64 (used by the config loader).
- Constants: `DEFAULT_HOST_KEY_PATH = "/var/lib/parallax/host.key"`,
  `HOST_KEY_ENV = "PARALLAX_HOST_KEY_FILE"`, `BUNDLE_VERSION = 1`.

## Operator workflow

```bash
# 1. Have a config whose secrets are inline or in a sidecar.
# 2. Machine-bind them: encrypts secrets into a sealed bundle and rewrites
#    the config to reference it (creates the host keyfile if absent).
plx seal --config parallax.toml
# Optional: --output <bundle path>   (default <config-dir>/parallax.secrets.enc)
#           --host-key <path>        (default $PARALLAX_HOST_KEY_FILE or the path above)

# 3. plx check now reports the config alone is not a credential.
plx check --config parallax.toml
```

A `sealed` reference that cannot be opened produces a clear error distinguishing a
missing/insecure host keyfile from a wrong key or tampered bundle.

## Drift risks

The `version`/`bundle_id`/AEAD/AAD shape is a wire format for the sealed bundle —
changing it breaks existing bundles. Keep this page aligned with the secret-source
table in [Configuration Reference](Configuration-Reference.md) and the project
`SECURITY.md` secret-handling threat model.
