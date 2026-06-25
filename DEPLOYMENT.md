# ParallaX deployment

> **Local build. Binary-only upload. No source code on the VPS.**

ParallaX is designed to be deployed as a *local-build, binary-only* system:

- you build the Linux `plx` binary on a trusted local machine;
- you upload only the binary, the server config, and a hardened `systemd` unit;
- the VPS never sees the source tree, the client config, or any of your
  private key material that isn't strictly needed to serve traffic.

`scripts/deploy-vps.sh` automates the full pipeline. It has two front ends:

- **Guided wizard** — run with no arguments. Recommended the first time.
- **Explicit flags** — the same pipeline, scriptable for CI / repeat use.

`scripts/uninstall-vps.sh` is the symmetric tear-down.

---

## Guided wizard (recommended)

From the repository root on the local machine:

```bash
bash scripts/deploy-vps.sh
```

The wizard walks you through SSH target, camouflage origin, public address,
optional Polar Signals profiling, and confirmation. Polar Signals bearer
tokens are pasted at the prompt — no token file needed.

---

## One-command explicit deploy

```bash
bash scripts/deploy-vps.sh root@YOUR_VPS_IP cloudflare.com
```

That command will:

1. generate fresh local configs under `target/parallax-deploy/<host>/`;
2. validate the server and client configs (`plx check`);
3. probe the camouflage target (`plx probe`);
4. build a Linux `plx` binary locally;
5. enable and verify TCP BBR + `fq` on the VPS;
6. upload the binary, `parallax.server.toml`, and the generated `parallax.service` unit to the VPS;
7. install and restart `parallax.service` through systemd.

The generated client config stays local at:

```text
target/parallax-deploy/<host>/parallax.client.toml
```

The uploaded server config is installed at:

```text
/etc/parallax/parallax.toml
```

---

## VPS TCP BBR tuning

The deploy script enables VPS-side BBR by default because ParallaX's
single-flow TCP transport is sensitive to congestion control on
high-latency links.

During remote install it:

1. checks whether `bbr` is in `net.ipv4.tcp_available_congestion_control`;
2. loads `tcp_bbr` with `modprobe` when needed;
3. persists module loading in `/etc/modules-load.d/parallax-bbr.conf`;
4. writes `/etc/sysctl.d/99-parallax-bbr.conf`;
5. applies sysctls immediately;
6. fails the deploy if `tcp_congestion_control=bbr` or `default_qdisc=fq`
   cannot be verified.

The `/etc/sysctl.d/99-parallax-bbr.conf` file contains:

```text
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.ipv4.tcp_rmem=4096 87380 67108864
net.ipv4.tcp_wmem=4096 65536 67108864
net.ipv4.tcp_mtu_probing=1
```

The script also writes a second, separate drop-in,
`/etc/sysctl.d/99-parallax-netbuf.conf`, **unconditionally** (even with
`--no-enable-bbr`, on Linux):

```text
net.core.rmem_max=67108864
net.core.wmem_max=67108864
```

These raise the socket-buffer maxima to 64 MiB. They are a prerequisite for the
`[transport]` `tcp_send_buffer_bytes` / `tcp_recv_buffer_bytes` overrides: without
them an explicit `SO_SNDBUF`/`SO_RCVBUF` is silently clamped to the kernel default
(~208 KiB). Raising the caps alone does not change autotuning — it only takes
effect when a `[transport]` buffer is actually configured.

Skip remote system tuning explicitly (this skips BBR only; the socket-buffer
maxima are still written):

```bash
bash scripts/deploy-vps.sh --no-enable-bbr root@YOUR_VPS_IP cloudflare.com
```

Manual verification on the VPS:

```bash
sysctl net.ipv4.tcp_available_congestion_control
sysctl net.ipv4.tcp_congestion_control
sysctl net.core.default_qdisc
```

---

## Optional: socket-buffer override for high-RTT / high-BDP links

Off by default. On a long intercontinental path the kernel's TCP autotuning can
under-provision the send/receive window, capping a single flow well below the
link's bandwidth-delay product (BDP). The `[transport]` section lets an operator
pin an explicit window when that happens. **Leave it unset unless you have
measured that autotuning is the bottleneck** — the default (autotuning) is what
keeps full Safari window parity.

Two prerequisites and one covertness rule:

1. The kernel maxima must already be raised (`net.core.wmem_max` /
   `net.core.rmem_max`); the deploy script writes 64 MiB unconditionally on
   Linux (see above). Without that, an explicit buffer is silently clamped to the
   ~208 KiB default — possibly *below* what autotuning would have reached.
2. Size the buffer to the path BDP: `BDP_bytes ≈ bandwidth_bytes_per_sec × RTT_sec`.
   Example: 100 Mbit/s × 300 ms ≈ 3.75 MiB, so `4 * 1024 * 1024` is a reasonable
   start. Over-sizing wastes memory and can add bufferbloat; under-sizing leaves
   throughput on the table.
3. **Covertness:** `tcp_send_buffer_bytes` is wire-invisible (it never changes any
   advertised value). `tcp_recv_buffer_bytes` *does* affect the advertised TCP
   window, so set it only on the **server** (the upload data-sink) and leave it
   unset on the client, where a fixed receive window would flatten the
   autotuning curve away from Safari's. The recv buffer is applied post-accept
   only, so the camouflage SYN is unaffected either way.

Server config (`/etc/parallax/server.toml`), to lift a slow client→server
upload on a high-RTT link:

```toml
[transport]
tcp_send_buffer_bytes = 4194304   # 4 MiB, wire-invisible
tcp_recv_buffer_bytes = 4194304   # 4 MiB, server-side upload sink only
```

Client config: prefer leaving `[transport]` unset for full browser parity. If a
slow server→client download is the measured bottleneck, only
`tcp_send_buffer_bytes` is safe to set on the client (it is wire-invisible);
keep `tcp_recv_buffer_bytes` unset.

A logged warning is emitted if the OS clamps the requested buffer below the
value asked for (the usual cause is an un-raised `*mem_max`).

---

## Local build modes

On **Linux**, the script uses native `cargo build --release` by default.

On **macOS**, it prefers Docker when available; otherwise it falls back to
local `cargo-zigbuild` and installs the missing local build helpers
(`zig`, `cargo-zigbuild`, and the Rust Linux target) when possible:

```bash
bash scripts/deploy-vps.sh root@YOUR_VPS_IP cloudflare.com
```

Force the no-Docker path explicitly:

```bash
bash scripts/deploy-vps.sh --build-mode zigbuild root@YOUR_VPS_IP cloudflare.com
```

---

## Optional Polar Signals Cloud profiling

Polar Signals Cloud uses the Parca Agent protocol. ParallaX keeps this
integration opt-in because continuous profiling uploads process symbols,
function names, binary paths, and timing data to a third-party backend.

Use it for staging or short production investigations, **not** as a
default always-on setting for sensitive nodes.

1. Put the Polar Signals bearer token in a local file that is not committed:

   ```bash
   printf '%s' 'psc_v1_YOUR_64_HEX_CHARS' > /tmp/parallax-polar.token
   chmod 600 /tmp/parallax-polar.token
   ```

2. Copy the Polar Signals project UUID from the Cloud project settings. The
   deploy script intentionally rejects project names here because Cloud
   writes need the exact `projectID` gRPC metadata.

3. Deploy with the profiler-friendly Cargo profile. `polar-cloud` refuses
   non-`profiling` builds so the VPS binary keeps embedded DWARF symbols
   for line-level flamegraphs.

   ```bash
   bash scripts/deploy-vps.sh \
     --profile-mode polar-cloud \
     --polar-token-file /tmp/parallax-polar.token \
     --polar-project-id YOUR_POLAR_PROJECT_UUID \
     --cargo-profile profiling \
     root@YOUR_VPS_IP \
     cloudflare.com
   ```

The deploy script uploads the token to:

```text
/etc/parallax/polarsignals.token
```

and installs:

```text
/etc/systemd/system/parca-agent.service
/etc/parallax/polarsignals.env
```

If `parca-agent` is missing, the script installs it through the official
snap package on the VPS. The generated systemd unit calls the stable snap
launcher path `/snap/bin/parca-agent` directly, avoiding boot-order races
with `/usr/local/bin` compatibility links. Use `--parca-agent-channel edge`
only if you explicitly want the snap edge channel.

The default remote store is:

```text
grpc.polarsignals.com:443
```

The Parca Agent local HTTP endpoint is bound to:

```text
127.0.0.1:7071
```

so it is not exposed publicly. To inspect it manually:

```bash
ssh -L 7071:127.0.0.1:7071 root@YOUR_VPS_IP
```

then open:

```text
http://127.0.0.1:7071
```

Check the profiler service:

```bash
ssh root@YOUR_VPS_IP 'sudo systemctl status parca-agent --no-pager'
ssh root@YOUR_VPS_IP 'sudo journalctl -u parca-agent -n 120 --no-pager'
```

**Security notes:**

- `parca-agent` must run with elevated privileges for eBPF profiling.
- Do not pass the Polar token directly on the command line.
- Do not enable process command-line metadata; ParallaX intentionally does
  not set that Parca Agent flag.
- Use `--cargo-profile release` for normal production. Polar Signals Cloud
  deployments use `--cargo-profile profiling`, which embeds full DWARF
  symbols and keeps the binary unstripped for useful flamegraphs.

---

## Explicit production form

Use the explicit form when the SSH name is not the same as the public
address that clients should dial:

```bash
bash scripts/deploy-vps.sh \
  --host root@my-ssh-alias \
  --dest cloudflare.com \
  --server-addr YOUR_VPS_IP:443
```

`--reuse-config` reuses the already-generated configs under
`target/parallax-deploy/<host>/` instead of regenerating them. It requires both
`parallax.server.toml` and `parallax.client.toml` to still exist there and aborts
if the deploy directory was removed; it does not fetch anything back from the VPS.

For unattended / CI use:

```bash
bash scripts/deploy-vps.sh --non-interactive \
  --host root@YOUR_VPS_IP \
  --dest cloudflare.com \
  --server-addr YOUR_VPS_IP:443
```

`--dry-run` prints the full pipeline without executing it.

---

## Start the local client

After the VPS deploy finishes, run this on the local machine:

```bash
plx client -c target/parallax-deploy/<host>/parallax.client.toml
```

It listens on:

```text
127.0.0.1:1080
```

Test with:

```bash
curl --socks5-hostname 127.0.0.1:1080 https://ifconfig.me
```

If the returned IP is the VPS IP, the tunnel is working.

---

## Domestic-path verification

Use a machine that is actually on the target restricted network. Do not
use a machine that is already routed through another VPN/proxy as the
final proof.

Run:

```bash
plx client -c parallax.client.toml
curl --socks5-hostname 127.0.0.1:1080 https://ifconfig.me
```

Then compare:

```bash
curl https://TARGET_SITE/ -I
curl --socks5-hostname 127.0.0.1:1080 https://TARGET_SITE/ -I
```

The useful signal is:

```text
direct connection fails or is blocked
ParallaX SOCKS connection succeeds
```

---

## Server operations

Check status:

```bash
ssh root@YOUR_VPS_IP 'sudo systemctl status parallax --no-pager'
```

View logs:

```bash
ssh root@YOUR_VPS_IP 'sudo journalctl -u parallax -n 80 --no-pager'
```

Restart:

```bash
ssh root@YOUR_VPS_IP 'sudo systemctl restart parallax'
```

---

## Uninstall

```bash
bash scripts/uninstall-vps.sh
```

The guided uninstaller removes ParallaX from one VPS and can remove the
local client configuration generated by `scripts/deploy-vps.sh`. Explicit
flags mirror the deployer (`--host`, `--service-name`, `--keep-local`,
`--remove-parca-agent`, `--dry-run`, `--yes`, `--non-interactive`, …).
Run `bash scripts/uninstall-vps.sh --help` for the full list.

---

## Notes

- The deploy script does not change local system proxy settings and does
  not touch Surge or any other client-side proxy manager.
- The deploy script does not enable a remote firewall. If `ufw` is already
  active, it only attempts to allow TCP/443.
- Generated TOML files contain secrets and are ignored by git.
- Server config files are installed with mode `0600` and are validated by
  `plx serve` on every start — incorrect ownership or permissions cause
  the service to refuse to start.
