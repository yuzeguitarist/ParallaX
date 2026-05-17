# Systemd Service & Security Hardening
Relevant source files

- [.gitignore](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/.gitignore)
- [DEPLOYMENT.md](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/DEPLOYMENT.md?plain=1)
- [scripts/deploy-vps.sh](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/scripts/deploy-vps.sh)

The ParallaX deployment model is designed for a local-build, binary-only workflow to ensure that sensitive protocol source code and cryptographic logic never reside on an untrusted VPS [DEPLOYMENT.md#3-9](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/DEPLOYMENT.md?plain=1#L3-L9) The `parallax.service` systemd unit serves as the primary execution environment on the server, implementing multiple layers of Linux kernel-level hardening to minimize the attack surface of the `plx` binary.

## Systemd Unit Configuration

The `parallax.service` unit is dynamically generated and installed by the `deploy-vps.sh` script [scripts/deploy-vps.sh#282-311](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/scripts/deploy-vps.sh#L282-L311) It encapsulates the `plx server` process with restricted privileges and isolated filesystem access.

### Security Directives

The service utilizes several `systemd.exec` security features:

| Directive | Purpose | Implementation Detail |
| --- | --- | --- |
| `AmbientCapabilities` | Privilege Escalation | Set to `CAP_NET_BIND_SERVICE` to allow the binary to bind to port 443 without running as `root`[scripts/deploy-vps.sh#293](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/scripts/deploy-vps.sh#L293-L293) |
| `NoNewPrivileges` | Process Hardening | Prevents the process and its children from gaining new privileges via `setuid` or `setgid` bits [scripts/deploy-vps.sh#294](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/scripts/deploy-vps.sh#L294-L294) |
| `ProtectSystem` | Filesystem Integrity | Set to `full`. Mounts `/usr`, `/boot`, and `/etc` as read-only for the service [scripts/deploy-vps.sh#295](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/scripts/deploy-vps.sh#L295-L295) |
| `ProtectHome` | Data Privacy | Set to `true`. Makes `/home`, `/root`, and `/run/user` empty and inaccessible [scripts/deploy-vps.sh#296](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/scripts/deploy-vps.sh#L296-L296) |
| `PrivateTmp` | Temporary Isolation | Sets up a private `/tmp` and `/var/tmp` namespace, invisible to other processes [scripts/deploy-vps.sh#297](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/scripts/deploy-vps.sh#L297-L297) |
| `Restart` | Availability | Configured as `on-failure` with a 5-second delay to ensure service persistence [scripts/deploy-vps.sh#290-291](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/scripts/deploy-vps.sh#L290-L291) |

Sources:[scripts/deploy-vps.sh#282-311](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/scripts/deploy-vps.sh#L282-L311)[DEPLOYMENT.md#3-9](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/DEPLOYMENT.md?plain=1#L3-L9)

## Filesystem Permissions & Ownership

The deployment script enforces strict POSIX permissions to protect the configuration secrets (such as the Pre-Shared Key) and the binary itself.

### Layout and Access Control

1. Configuration (`/etc/parallax/parallax.toml`):

- Permissions: `0600` (Read/Write for owner only).
- Ownership: Managed by the user running the service (typically `root` or a dedicated service user) [scripts/deploy-vps.sh#30](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/scripts/deploy-vps.sh#L30-L30)[scripts/deploy-vps.sh#276](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/scripts/deploy-vps.sh#L276-L276)
2. Binary (`/usr/local/bin/plx`):

- Permissions: `0755` (Read/Execute for all, Write for owner).
- Ownership: Root [scripts/deploy-vps.sh#29](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/scripts/deploy-vps.sh#L29-L29)[scripts/deploy-vps.sh#274](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/scripts/deploy-vps.sh#L274-L274)

### Data Flow: Deployment to Service

The following diagram illustrates how the `deploy-vps.sh` script transitions from the local build environment to the hardened systemd state on the VPS.

Systemd Deployment & Hardening Flow

[Flowchart Diagram]

Sources:[scripts/deploy-vps.sh#109-128](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/scripts/deploy-vps.sh#L109-L128)[scripts/deploy-vps.sh#267-315](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/scripts/deploy-vps.sh#L267-L315)[DEPLOYMENT.md#10-26](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/DEPLOYMENT.md?plain=1#L10-L26)

## Configuration Lifecycle & Key Rotation

ParallaX supports a `--reuse-config` workflow that allows administrators to update the binary or service settings without rotating the cryptographic keys or changing the client configuration.

### The `--reuse-config` Workflow

When executing `scripts/deploy-vps.sh --reuse-config`, the script bypasses the `plx init` phase [scripts/deploy-vps.sh#117-128](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/scripts/deploy-vps.sh#L117-L128) This is critical for:

1. Binary Updates: Patching the `plx` server without forcing all clients to update their `parallax.client.toml`.
2. Infrastructure Changes: Moving the server to a different IP while keeping the same Pre-Shared Key (PSK) and identity.

### Key Rotation Procedure

To perform a full security rotation (changing the PSK and ML-KEM keys):

1. Run `deploy-vps.sh`without the `--reuse-config` flag.
2. The script calls `cargo run ... -- init`[scripts/deploy-vps.sh#123](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/scripts/deploy-vps.sh#L123-L123)
3. A new `parallax.server.toml` is generated and uploaded.
4. The systemd service is restarted [scripts/deploy-vps.sh#315](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/scripts/deploy-vps.sh#L315-L315)
5. The administrator must distribute the newly generated `target/parallax-deploy/<host>/parallax.client.toml` to all clients [scripts/deploy-vps.sh#45](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/scripts/deploy-vps.sh#L45-L45)

Sources:[scripts/deploy-vps.sh#38](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/scripts/deploy-vps.sh#L38-L38)[scripts/deploy-vps.sh#117-128](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/scripts/deploy-vps.sh#L117-L128)[DEPLOYMENT.md#56-60](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/DEPLOYMENT.md?plain=1#L56-L60)

## Process Monitoring and Logs

Because the service runs under systemd, it integrates with `journald` for secure log management. Administrators can inspect the server's behavior and potential probing attempts using standard system tools.

Entity Mapping: Management Commands

| Task | Command | Code/Unit Reference |
| --- | --- | --- |
| Check Status | `systemctl status parallax` | `parallax.service`[scripts/deploy-vps.sh#31](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/scripts/deploy-vps.sh#L31-L31) |
| View Logs | `journalctl -u parallax` | `StandardOutput=journal` (Default). |
| Verify Listen | `ss -tulpn | grep plx` |
| Config Validation | `plx check -c <path>` | `plx check` subcommand [scripts/deploy-vps.sh#130](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/scripts/deploy-vps.sh#L130-L130) |

Sources:[DEPLOYMENT.md#116-135](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/DEPLOYMENT.md?plain=1#L116-L135)[scripts/deploy-vps.sh#130-131](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/scripts/deploy-vps.sh#L130-L131)