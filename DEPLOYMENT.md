# ParallaX private deployment

This project should be deployed as a **local-build, binary-only** system:

- do not clone the source repository on an untrusted VPS
- do not put private protocol code into a public repository
- build the Linux binary on the trusted local machine
- upload only the `plx` binary, the server config, and a systemd unit

## One-command VPS deploy

From the repository root on the local machine:

```bash
bash scripts/deploy-vps.sh root@YOUR_VPS_IP cloudflare.com
```

That command will:

1. generate fresh local configs under `target/parallax-deploy/<host>/`
2. validate the server and client configs
3. probe the camouflage target
4. build a Linux `plx` binary locally
5. upload only the binary and `parallax.server.toml` to the VPS
6. install and restart `parallax.service` through systemd

On macOS, the script first uses Docker when available. If Docker is not
installed, it falls back to local `cargo-zigbuild` and installs the missing
local build helpers (`zig`, `cargo-zigbuild`, and the Rust Linux target) when
possible:

```bash
bash scripts/deploy-vps.sh root@YOUR_VPS_IP cloudflare.com
```

To force the no-Docker path:

```bash
bash scripts/deploy-vps.sh --build-mode zigbuild root@YOUR_VPS_IP cloudflare.com
```

On Linux, it uses native `cargo build --release` by default.

## Optional Polar Signals Cloud profiling

Polar Signals Cloud uses the Parca Agent protocol. ParallaX keeps this
integration opt-in because continuous profiling uploads process symbols,
function names, binary paths, and timing data to a third-party backend.

Use it for staging or short production investigations, not as a default
always-on setting for sensitive nodes.

1. Put the Polar Signals bearer token in a local file that is not committed:

   ```bash
   printf '%s' 'psc_v1_YOUR_64_HEX_CHARS' > /tmp/parallax-polar.token
   chmod 600 /tmp/parallax-polar.token
   ```

2. Copy the Polar Signals project UUID from the Cloud project settings. The
   deploy script intentionally rejects project names here because Cloud writes
   need the exact `projectID` gRPC metadata.

3. Deploy with the profiler-friendly Cargo profile. `polar-cloud` refuses
   non-`profiling` builds so the VPS binary keeps embedded DWARF symbols for
   line-level flamegraphs.

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

If `parca-agent` is missing, the script installs it through the official snap
package on the VPS. The generated systemd unit calls the stable snap launcher
path `/snap/bin/parca-agent` directly, avoiding boot-order races with
`/usr/local/bin` compatibility links. Use `--parca-agent-channel edge` only if
you explicitly want the snap edge channel.

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

Security notes:

- `parca-agent` must run with elevated privileges for eBPF profiling.
- Do not pass the Polar token directly on the command line.
- Do not enable process command-line metadata; ParallaX intentionally does not
  set that Parca Agent flag.
- Use `--cargo-profile release` for normal production. Polar Signals Cloud
  deployments use `--cargo-profile profiling`, which embeds full DWARF symbols
  and keeps the binary unstripped for useful flamegraphs.

## Explicit production form

Use the explicit form when the SSH name is not the same as the public address
that clients should dial:

```bash
bash scripts/deploy-vps.sh \
  --host root@my-ssh-alias \
  --dest cloudflare.com \
  --server-addr YOUR_VPS_IP:443
```

The generated client config stays local:

```text
target/parallax-deploy/<host>/parallax.client.toml
```

If that local deploy directory was removed later, `--reuse-config` will fetch
the existing server config back from `/etc/parallax/parallax.toml` over SSH and
perform a server-only redeploy. Your already-working local client config is not
regenerated or changed.

The uploaded server config is installed as:

```text
/etc/parallax/parallax.toml
```

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

## Beijing / domestic-path verification

Use a machine that is actually on the target domestic network. Do not use a
machine that is already routed through another VPN/proxy as the final proof.

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

## Notes

- The deploy script does not change local system proxy settings and does not
  touch Surge.
- The deploy script does not enable a remote firewall. If `ufw` is already
  active, it only attempts to allow TCP/443.
- Generated TOML files contain secrets and are ignored by git.
