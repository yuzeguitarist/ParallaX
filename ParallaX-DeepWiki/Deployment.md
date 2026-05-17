# Deployment
Relevant source files

- [Cargo.toml](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/Cargo.toml)
- [DEPLOYMENT.md](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/DEPLOYMENT.md?plain=1)
- [scripts/deploy-vps.sh](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/scripts/deploy-vps.sh)

ParallaX is designed as a local-build, binary-only deployment system [DEPLOYMENT.md#3-9](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/DEPLOYMENT.md?plain=1#L3-L9) To maintain maximum operational security, the source code is never cloned onto the remote VPS. Instead, the deployment pipeline focuses on cross-compiling the binary and generating cryptographic configurations on a trusted local machine before pushing the final artifacts to the server.

### Deployment Workflow Overview

The deployment process is orchestrated by the `scripts/deploy-vps.sh` script. This script automates the transition from a local development environment to a production-ready remote instance.

The following diagram illustrates the relationship between the local environment, the deployment script, and the remote system entities:

Deployment Pipeline Architecture

[Flowchart Diagram]

Sources:[scripts/deploy-vps.sh#1-48](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/scripts/deploy-vps.sh#L1-L48)[DEPLOYMENT.md#1-25](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/DEPLOYMENT.md?plain=1#L1-L25)

---

### VPS Deployment Script

The `scripts/deploy-vps.sh` script is the primary entry point for deployment. It manages several critical phases of the lifecycle:

1. Configuration Generation: Invokes `plx init` to create unique cryptographic keys and configuration files [scripts/deploy-vps.sh#123-127](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/scripts/deploy-vps.sh#L123-L127)
2. Target Validation: Runs `plx probe` against the chosen camouflage domain to ensure it is suitable for mimicking [scripts/deploy-vps.sh#133-139](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/scripts/deploy-vps.sh#L133-L139)
3. Cross-Compilation: Supports multiple build modes including `native` (for Linux hosts), `docker` (using `rust:1-bookworm`), and `zigbuild` (using `cargo-zigbuild` for macOS-to-Linux cross-compilation) [scripts/deploy-vps.sh#147-183](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/scripts/deploy-vps.sh#L147-L183)
4. Remote Staging: Transfers the binary and server configuration to the VPS via SSH/SCP [scripts/deploy-vps.sh#255-275](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/scripts/deploy-vps.sh#L255-L275)

For a detailed walkthrough of the script logic and build modes, see [VPS Deployment Script](#8.1).

Sources:[scripts/deploy-vps.sh#32-42](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/scripts/deploy-vps.sh#L32-L42)[scripts/deploy-vps.sh#142-186](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/scripts/deploy-vps.sh#L142-L186)

---

### Systemd Service & Security Hardening

Once the binary and configuration are uploaded, the deployment script installs a `systemd` unit to manage the ParallaX process. This unit is designed with security hardening in mind to minimize the attack surface of the proxy server.

Service-to-Code Mapping

[Flowchart Diagram]

The deployment ensures that:

- The binary has the necessary capabilities to bind to privileged ports (like 443) without running as a full-privilege user [scripts/deploy-vps.sh#230-245](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/scripts/deploy-vps.sh#L230-L245)
- Configuration files are restricted to `0600` permissions to protect the Pre-Shared Keys (PSK) [scripts/deploy-vps.sh#272](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/scripts/deploy-vps.sh#L272-L272)
- The service can be updated using a `--reuse-config` workflow that preserves existing keys while updating the binary [scripts/deploy-vps.sh#117-129](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/scripts/deploy-vps.sh#L117-L129)

For details on the systemd unit configuration and filesystem permissions, see [Systemd Service & Security Hardening](#8.2).

Sources:[scripts/deploy-vps.sh#220-250](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/scripts/deploy-vps.sh#L220-L250)[DEPLOYMENT.md#116-135](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/DEPLOYMENT.md?plain=1#L116-L135)

---

### Post-Deployment Verification

After successful deployment, the script provides instructions for starting the local client using the generated `parallax.client.toml`[DEPLOYMENT.md#68-88](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/DEPLOYMENT.md?plain=1#L68-L88)

| Action | Command | Purpose |
| --- | --- | --- |
| Start Client | `plx client -c <config_path>` | Establish the local SOCKS5 tunnel. |
| Verify Tunnel | `curl --socks5-hostname 127.0.0.1:1080 https://ifconfig.me` | Confirm the outgoing IP matches the VPS. |
| Check Logs | `journalctl -u parallax` | Monitor server-side handshake and relay events. |

Sources:[DEPLOYMENT.md#44-47](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/DEPLOYMENT.md?plain=1#L44-L47)[DEPLOYMENT.md#82-88](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/DEPLOYMENT.md?plain=1#L82-L88)[DEPLOYMENT.md#124-127](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/DEPLOYMENT.md?plain=1#L124-L127)