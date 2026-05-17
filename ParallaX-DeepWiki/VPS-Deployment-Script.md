# VPS Deployment Script
Relevant source files

- [DEPLOYMENT.md](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/DEPLOYMENT.md?plain=1)
- [scripts/deploy-vps.sh](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/scripts/deploy-vps.sh)

The `scripts/deploy-vps.sh` script facilitates a local-build, binary-only deployment model [DEPLOYMENT.md#3-8](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/DEPLOYMENT.md?plain=1#L3-L8) This ensures that sensitive source code and build environments remain on a trusted local machine, while only the compiled `plx` binary and necessary configurations are uploaded to the remote VPS [DEPLOYMENT.md#5-9](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/DEPLOYMENT.md?plain=1#L5-L9)

## Deployment Lifecycle

The deployment process is orchestrated through several distinct phases, from environment validation to remote service activation.

### 1. Environment Preparation & Config Generation

The script first validates the local environment and generates the necessary cryptographic secrets and configuration files using the `plx init` subcommand [scripts/deploy-vps.sh#123-127](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/scripts/deploy-vps.sh#L123-L127)

- Config Generation: Unless `--reuse-config` is specified, the script removes existing configs and generates a fresh pair of `parallax.server.toml` and `parallax.client.toml`[scripts/deploy-vps.sh#117-128](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/scripts/deploy-vps.sh#L117-L128)
- Validation: The generated configs are immediately validated using `plx check` to ensure schema correctness before proceeding to build [scripts/deploy-vps.sh#130-131](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/scripts/deploy-vps.sh#L130-L131)
- Target Probing: The script runs `plx probe` against the specified camouflage destination (`--dest`) to verify its suitability (TLS 1.3 support, ALPN, etc.) [scripts/deploy-vps.sh#133-139](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/scripts/deploy-vps.sh#L133-L139)

### 2. Cross-Compilation Build Modes

The script supports four build modes to ensure a Linux-compatible binary is produced regardless of the host OS [scripts/deploy-vps.sh#147-159](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/scripts/deploy-vps.sh#L147-L159)

| Mode | Description | Logic |
| --- | --- | --- |
| `native` | Uses local `cargo build` | Default on Linux hosts [scripts/deploy-vps.sh#150](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/scripts/deploy-vps.sh#L150-L150) |
| `docker` | Builds inside a container | Uses `rust:1-bookworm` to produce a glibc-compatible binary [scripts/deploy-vps.sh#172-182](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/scripts/deploy-vps.sh#L172-L182) |
| `zigbuild` | Uses `cargo-zigbuild` | Uses the Zig toolchain as a linker for easy cross-compilation [scripts/deploy-vps.sh#165-170](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/scripts/deploy-vps.sh#L165-L170) |
| `auto` | Heuristic selection | Linux → `native`; macOS with Docker → `docker`; otherwise → `zigbuild`[scripts/deploy-vps.sh#148-156](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/scripts/deploy-vps.sh#L148-L156) |

### 3. Remote Staging and Installation

Once the binary is built, the script performs the following remote operations over SSH:

- Directory Setup: Creates `/etc/parallax` and ensures correct permissions [scripts/deploy-vps.sh#267-271](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/scripts/deploy-vps.sh#L267-L271)
- Binary Upload: Transfers the `plx` binary to the remote path (default `/usr/local/bin/plx`) [scripts/deploy-vps.sh#282-286](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/scripts/deploy-vps.sh#L282-L286)
- Config Upload: Transfers the server-specific TOML configuration [scripts/deploy-vps.sh#288-290](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/scripts/deploy-vps.sh#L288-L290)
- Systemd Integration: Generates and uploads a `parallax.service` unit file, then reloads the daemon and starts the service [scripts/deploy-vps.sh#292-303](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/scripts/deploy-vps.sh#L292-L303)

### 4. Firewall Configuration

The script attempts to ensure the service is reachable by checking for `ufw` (Uncomplicated Firewall). If `ufw` is active, it explicitly allows the configured server port (default TCP/443) [scripts/deploy-vps.sh#273-280](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/scripts/deploy-vps.sh#L273-L280)

Sources:

- [scripts/deploy-vps.sh#109-140](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/scripts/deploy-vps.sh#L109-L140) (Config generation and probing)
- [scripts/deploy-vps.sh#142-186](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/scripts/deploy-vps.sh#L142-L186) (Build mode implementation)
- [scripts/deploy-vps.sh#265-304](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/scripts/deploy-vps.sh#L265-L304) (Remote installation)
- [DEPLOYMENT.md#1-43](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/DEPLOYMENT.md?plain=1#L1-L43) (Deployment philosophy and usage)

---

## Data Flow: Local to Remote

The following diagram illustrates the flow of artifacts from the local development machine to the remote VPS.

### Deployment Artifact Pipeline

[Flowchart Diagram]

Sources:

- [scripts/deploy-vps.sh#123-127](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/scripts/deploy-vps.sh#L123-L127) (Config generation)
- [scripts/deploy-vps.sh#161-183](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/scripts/deploy-vps.sh#L161-L183) (Binary build paths)
- [scripts/deploy-vps.sh#282-300](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/scripts/deploy-vps.sh#L282-L300) (Remote file transfer)

---

## Technical Implementation: Build Logic

The `build_linux_binary` function is the core of the cross-platform support. It manages environment-specific complexities like Docker volume mounts and Zig toolchain installation.

### Logic Flow for `build_linux_binary`

[Flowchart Diagram]

### Build Helper Management

For `zigbuild` mode, the script includes self-bootstrapping logic to install dependencies on macOS using Homebrew:

- `ensure_zigbuild_tools`: Installs `zig` and `cargo-zigbuild` if missing [scripts/deploy-vps.sh#225-230](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/scripts/deploy-vps.sh#L225-L230)
- `ensure_rust_target`: Uses `rustup target add` to install the required Linux target triple [scripts/deploy-vps.sh#188-197](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/scripts/deploy-vps.sh#L188-L197)
- `maybe_install_build_tool`: General wrapper for `brew install` or `cargo install`[scripts/deploy-vps.sh#199-223](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/scripts/deploy-vps.sh#L199-L223)

Sources:

- [scripts/deploy-vps.sh#142-186](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/scripts/deploy-vps.sh#L142-L186) (Main build function)
- [scripts/deploy-vps.sh#188-230](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/scripts/deploy-vps.sh#L188-L230) (Toolchain management)

---

## Deployment Configuration Parameters

The script accepts several arguments that map directly to the `plx init` command and the subsequent systemd service setup.

| Parameter | Script Variable | Default | Code Reference |
| --- | --- | --- | --- |
| SSH Target | `HOST` | (Required) | [scripts/deploy-vps.sh#23](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/scripts/deploy-vps.sh#L23-L23) |
| Camouflage Domain | `DEST` | (Required) | [scripts/deploy-vps.sh#24](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/scripts/deploy-vps.sh#L24-L24) |
| Client Dial Addr | `SERVER_ADDR` | `host:443` | [scripts/deploy-vps.sh#25-103](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/scripts/deploy-vps.sh#L25-L103) |
| VPS Listen Addr | `SERVER_LISTEN` | `0.0.0.0:443` | [scripts/deploy-vps.sh#27](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/scripts/deploy-vps.sh#L27-L27) |
| Local Proxy Port | `CLIENT_LISTEN` | `127.0.0.1:1080` | [scripts/deploy-vps.sh#28](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/scripts/deploy-vps.sh#L28-L28) |
| Linux Target | `LINUX_TARGET` | `x86_64-unknown-linux-gnu` | [scripts/deploy-vps.sh#34](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/scripts/deploy-vps.sh#L34-L34) |

### Service Generation

The `generate_systemd_unit` function creates a service file with the following characteristics:

- Type: `simple`[scripts/deploy-vps.sh#240](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/scripts/deploy-vps.sh#L240-L240)
- Command: Calls the binary with the `serve` subcommand and the uploaded config [scripts/deploy-vps.sh#244](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/scripts/deploy-vps.sh#L244-L244)
- Restart: `always` with a 5-second delay [scripts/deploy-vps.sh#245-246](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/scripts/deploy-vps.sh#L245-L246)
- Capabilities: Requests `CAP_NET_BIND_SERVICE` to allow binding to port 443 as a non-root user [scripts/deploy-vps.sh#248](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/scripts/deploy-vps.sh#L248-L248)

Sources:

- [scripts/deploy-vps.sh#23-42](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/scripts/deploy-vps.sh#L23-L42) (CLI argument definitions)
- [scripts/deploy-vps.sh#232-263](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/scripts/deploy-vps.sh#L232-L263) (Systemd unit generation)