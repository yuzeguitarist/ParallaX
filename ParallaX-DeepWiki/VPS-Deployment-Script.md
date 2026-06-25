# VPS Deployment Script

> Navigation: [Index](README.md) | [Deployment](Deployment.md) | [Systemd Hardening](Systemd-Service-&-Security-Hardening.md)

## Script

```text
scripts/deploy-vps.sh
```

The script is intentionally self-contained Bash so a normal operator can deploy
without copying source code to the VPS.

## Build modes

| Mode | Behavior |
|---|---|
| `auto` | Prefer native cargo on Linux, then Docker or `cargo-zigbuild` on macOS. |
| `native` | Build with local cargo for the target host. |
| `docker` | Build inside a Rust Docker image. |
| `zigbuild` | Cross-compile with `cargo-zigbuild`. |

Relevant flags:

```text
--build-mode <auto|docker|zigbuild|native>
--linux-target <triple>
--cargo-profile <profile>
--docker-image <image>
--install-build-tools
--no-install-build-tools
```

## Config generation and reuse

By default the script generates fresh configs through the project CLI and stores
them under `target/parallax-deploy/<host>/`. `--reuse-config` reuses those local
files and verifies the deployed replay-cache path is compatible with the systemd
sandbox.

## Remote staging

Remote staging uses a private temporary directory created with `umask 077` and
`mktemp -d`. The script uploads staged artifacts and installs them with explicit
modes:

- binary: `0755`
- server config: `0600`
- systemd unit: `0644`

## Network tuning

By default the script attempts to enable, in `/etc/sysctl.d/99-parallax-bbr.conf`:

```text
tcp_bbr
net.core.default_qdisc=fq
```

Use `--no-enable-bbr` to skip this step.

Separately, it always writes `/etc/sysctl.d/99-parallax-netbuf.conf` (even with
`--no-enable-bbr`, on Linux), raising the socket-buffer maxima to 64 MiB:

```text
net.core.rmem_max=67108864
net.core.wmem_max=67108864
```

These are the prerequisite for the `[transport]` `tcp_send_buffer_bytes` /
`tcp_recv_buffer_bytes` overrides — without them an explicit `SO_*BUF` is clamped
to the kernel default. Raising the caps does not change autotuning on its own.

If UFW is active, the script allows `443/tcp` with a ParallaX comment.

## Profiling mode

`--profile-mode polar-cloud` can install/configure `parca-agent` and send
profiles to Polar Signals Cloud. Required inputs include:

- bearer token or token file
- Polar project UUID
- remote store address
- node label and labels

Default mode is `none`.

## Safety checks

The script validates:

- SSH target shape
- absolute remote paths
- service-name characters
- no spaces/control characters in sensitive flag values
- mutually exclusive Polar token inputs
- config reuse preconditions

Related pages: [Deployment](Deployment.md) and
[Systemd Service & Security Hardening](Systemd-Service-&-Security-Hardening.md).
