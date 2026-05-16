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

On macOS, the script uses local Docker by default to produce a Linux binary:

```bash
bash scripts/deploy-vps.sh --build-mode docker root@YOUR_VPS_IP cloudflare.com
```

On Linux, it uses native `cargo build --release` by default.

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
