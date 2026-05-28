# Deployment

> Navigation: [Index](README.md) | [VPS Script](VPS-Deployment-Script.md) | [Systemd Hardening](Systemd-Service-&-Security-Hardening.md)

## Deployment model

ParallaX uses a local-build, binary-only VPS deployment model:

1. Build the Linux `plx` binary on a trusted local machine.
2. Generate server/client configs locally.
3. Upload only the binary, server config, and systemd unit.
4. Keep the source tree and local client config off the VPS.

The main implementation is `scripts/deploy-vps.sh`.

## Guided deploy

```bash
bash scripts/deploy-vps.sh
```

The wizard asks for the SSH target, camouflage destination, server address,
optional advanced settings, and optional profiling integration.

## Explicit deploy

```bash
bash scripts/deploy-vps.sh root@1.2.3.4 cloudflare.com
```

Equivalent flag form:

```bash
bash scripts/deploy-vps.sh \
  --host root@1.2.3.4 \
  --dest cloudflare.com \
  --server-addr 1.2.3.4:443
```

## Local artifacts

Deploy artifacts are staged under:

```text
target/parallax-deploy/<host>/
```

Typical contents:

- `plx` build output source path
- `parallax.server.toml`
- `parallax.client.toml`
- `parallax.service`
- optional Polar Signals / parca-agent files

Use `--reuse-config` to reuse generated configs from that directory.

## Remote artifacts

Defaults:

| Artifact | Default path |
|---|---|
| binary | `/usr/local/bin/plx` |
| server config | `/etc/parallax/parallax.toml` |
| state directory | `/var/lib/parallax` |
| systemd unit | `/etc/systemd/system/parallax.service` |
| replay cache | `/var/lib/parallax/parallax-replay.cache` |

The server config is installed with mode `0600`.

## Post-deploy client

```bash
plx client -c target/parallax-deploy/<host>/parallax.client.toml
curl --socks5-hostname 127.0.0.1:1080 https://ifconfig.me
```

## Uninstall

Guided:

```bash
bash scripts/uninstall-vps.sh
```

Explicit:

```bash
bash scripts/uninstall-vps.sh --host root@1.2.3.4 --yes
```

The uninstaller can remove the service, binary, config, local deploy directory,
BBR sysctl files, UFW rule, and optionally parca-agent.

Related pages: [VPS Deployment Script](VPS-Deployment-Script.md) and
[Systemd Service & Security Hardening](Systemd-Service-&-Security-Hardening.md).
