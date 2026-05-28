# Systemd Service & Security Hardening

> Navigation: [Index](README.md) | [Deployment](Deployment.md) | [Configuration](Configuration-Reference.md)

## Unit shape

`scripts/deploy-vps.sh` writes a `parallax.service` unit with:

```text
ExecStart=/usr/local/bin/plx serve -c /etc/parallax/parallax.toml
WorkingDirectory=/var/lib/parallax
Restart=always
RestartSec=3
LimitNOFILE=1048576
UMask=0077
```

The exact binary/config paths can be changed with deploy-script flags.

## Systemd sandboxing

The generated unit enables:

- `NoNewPrivileges=true`
- `ProtectSystem=strict`
- `ProtectHome=true`
- `PrivateTmp=true`
- `PrivateDevices=true`
- `ProtectClock=true`
- `ProtectControlGroups=true`
- `ProtectKernelLogs=true`
- `ProtectKernelModules=true`
- `ProtectKernelTunables=true`
- `LockPersonality=true`
- `MemoryDenyWriteExecute=true`
- `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`
- `RestrictNamespaces=true`
- `RestrictRealtime=true`
- `RestrictSUIDSGID=true`
- `SystemCallArchitectures=native`
- `ReadWritePaths=/var/lib/parallax`
- `AmbientCapabilities=CAP_NET_BIND_SERVICE`
- `CapabilityBoundingSet=CAP_NET_BIND_SERVICE`

`CAP_NET_BIND_SERVICE` allows binding to port 443 without making the service a
general-purpose privileged process.

## Filesystem layout

| Path | Mode / role |
|---|---|
| `/usr/local/bin/plx` | executable binary |
| `/etc/parallax/parallax.toml` | server config, installed `0600` |
| `/var/lib/parallax` | writable state directory |
| `/var/lib/parallax/parallax-replay.cache` | default replay cache |

The service only needs write access to `/var/lib/parallax`.

## In-process hardening

Before long-lived `serve` and `client` paths continue, ParallaX also attempts:

- no-core-dump rlimit
- non-dumpable process flag
- `mlock` for sensitive byte buffers
- `MADV_DONTDUMP` for sensitive buffers
- zeroization for secret-holding structures where practical

These protections are best-effort and platform-dependent; they complement, but
do not replace, file permissions and service sandboxing.

## Logs and debugging

```bash
ssh root@HOST 'systemctl status parallax --no-pager'
ssh root@HOST 'journalctl -u parallax -n 80 --no-pager'
```

Set `RUST_LOG=parallax=info` or a narrower filter when diagnosing handshake
transitions.

Related pages: [Replay Protection](Replay-Protection.md) and
[VPS Deployment Script](VPS-Deployment-Script.md).
