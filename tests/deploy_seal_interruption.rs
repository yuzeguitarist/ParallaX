//! Execute the emitted deployment payload with real sealing and injected failure.

#![cfg(unix)]

use std::{
    fs,
    io::{Seek, Write},
    os::unix::{fs::PermissionsExt, process::CommandExt},
    path::Path,
    process::Command,
};

use parallax::config::Config;

const STUB: &str = r#"
import json, os, pathlib, shutil, subprocess, sys
root = pathlib.Path(os.environ['VPS_ROOT'])
command = pathlib.Path(sys.argv[0]).name
args = sys.argv[1:]
with (root / 'commands.jsonl').open('a') as log:
    log.write(json.dumps([command, *args]) + '\n')
def checked(value):
    path = pathlib.Path(value)
    assert path.is_relative_to(root), 'mutation outside sandbox: ' + value
    return path
if command == 'install':
    paths, mode, directory = [], 0o755, False
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in ('-m', '-o', '-g'):
            if arg == '-m': mode = int(args[i + 1], 8)
            i += 2
        elif arg == '-d':
            directory = True
            i += 1
        else:
            paths.append(checked(arg))
            i += 1
    if directory:
        for path in paths:
            path.mkdir(parents=True, exist_ok=True)
            path.chmod(mode)
    else:
        source, destination = paths
        shutil.copyfile(source, destination)
        destination.chmod(mode)
        if (os.environ.get('FAIL_AFTER_BUNDLE') == '1'
                and destination == root / 'etc/parallax/parallax.toml.secrets.enc'):
            raise SystemExit(97)
elif command == 'rm':
    for arg in args:
        if arg.startswith('-'): continue
        path = checked(arg)
        if path.is_dir(): shutil.rmtree(path)
        else: path.unlink(missing_ok=True)
elif command == 'runuser':
    raise SystemExit(subprocess.run(args[args.index('--') + 1:]).returncode)
elif command == 'id':
    print(os.getuid())
elif command == 'uname':
    print('Darwin')
elif command == 'ufw':
    print('Status: inactive')
"#;

fn bash(script: &str, root: &Path, fail_after_bundle: bool) -> std::process::Output {
    // Feed the script through a private regular file: writing piped stdin before
    // reading output can deadlock against a child blocked on its stdout pipe.
    let mut input = tempfile::tempfile_in(root).unwrap();
    input.write_all(script.as_bytes()).unwrap();
    input.rewind().unwrap();
    let child = Command::new("bash")
        .arg("-s")
        .process_group(0)
        .env("VPS_ROOT", root)
        .env("TMPDIR", root)
        .env(
            "FAIL_AFTER_BUNDLE",
            if fail_after_bundle { "1" } else { "0" },
        )
        .env(
            "PATH",
            format!(
                "{}:{}",
                root.join("commands").display(),
                std::env::var("PATH").unwrap()
            ),
        )
        .stdin(input)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let group = rustix::process::Pid::from_child(&child);
    let (done, finished) = std::sync::mpsc::channel();
    let watchdog = std::thread::spawn(move || {
        if finished.recv_timeout(std::time::Duration::from_secs(20))
            == Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        {
            let _ = rustix::process::kill_process_group(group, rustix::process::Signal::KILL);
            return true;
        }
        false
    });
    let output = child.wait_with_output();
    let _ = done.send(());
    assert!(
        !watchdog.join().unwrap(),
        "sandbox bash exceeded 20 seconds"
    );
    output.unwrap()
}

fn fixture(root: &Path, domain: &str) -> std::path::PathBuf {
    let output = root.join(domain);
    fs::create_dir(&output).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_plx"))
        .args(["init", domain, "--inline-secrets", "--output"])
        .arg(&output)
        .output()
        .unwrap();
    assert!(result.status.success(), "{:?}", result);
    output.join("parallax.server.toml")
}

fn assert_same_config(actual: &Config, expected: &Config) {
    assert_eq!(actual.crypto.psk.as_b64(), expected.crypto.psk.as_b64());
    let actual = actual.server.as_ref().unwrap();
    let expected = expected.server.as_ref().unwrap();
    assert_eq!(actual.private_key.as_b64(), expected.private_key.as_b64());
    assert_eq!(
        actual.identity_secret_key.as_b64(),
        expected.identity_secret_key.as_b64()
    );
    assert_eq!(actual.authorized_sni, expected.authorized_sni);
    assert_eq!(actual.fallback_addr, expected.fallback_addr);
}

#[test]
fn interrupted_bundle_install_keeps_new_inline_config_consistent() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let host_key = root.join("host.key");
    std::env::set_var(parallax::secret_store::HOST_KEY_ENV, &host_key);
    let python = Command::new("python3")
        .args(["-c", "import sys; print(sys.executable)"])
        .output()
        .unwrap();
    assert!(python.status.success());
    let stub = root.join("stub");
    fs::write(
        &stub,
        format!(
            "#!{}\n{STUB}",
            String::from_utf8(python.stdout).unwrap().trim()
        ),
    )
    .unwrap();
    fs::set_permissions(&stub, fs::Permissions::from_mode(0o755)).unwrap();
    fs::create_dir(root.join("commands")).unwrap();
    fs::create_dir_all(root.join("etc/systemd/system")).unwrap();
    for command in [
        "install",
        "rm",
        "runuser",
        "id",
        "uname",
        "ufw",
        "chown",
        "systemctl",
    ] {
        std::os::unix::fs::symlink(&stub, root.join("commands").join(command)).unwrap();
    }

    // Generate the actual payload through install_remote; suppress transport only.
    let source = include_str!("../scripts/deploy-vps.sh");
    let generator = format!(
        "{}\nDRY_RUN=1\nENABLE_BBR=0\nSEAL_SECRETS=1\nREMOTE_SUDO=''\nSSH_TARGET=root@sandbox.invalid\nREUSE_CONFIG=0\n\
         trap 'rm -rf \"$SSH_CONTROL_DIR\"' EXIT\n\
         run() {{ if [[ \"${{!#}}\" == $'set -Eeuo pipefail\\n'* ]]; then printf 'REMOTE_SCRIPT\\n%s\\nEND_REMOTE_SCRIPT\\n' \"${{!#}}\"; fi; }}\n\
         install_remote /unused /unused/server.toml /unused/parallax.service\n",
        source.split("\nORIGINAL_ARGS=").next().unwrap()
    );
    let generated = bash(&generator, root, false);
    assert!(generated.status.success(), "{:?}", generated);
    let generated = String::from_utf8(generated.stdout).unwrap();
    let payload = generated
        .split_once("REMOTE_SCRIPT\n")
        .unwrap()
        .1
        .split_once("\nEND_REMOTE_SCRIPT")
        .unwrap()
        .0;
    let mut payload = payload.to_owned();
    for prefix in [
        "/etc/",
        "/var/lib/",
        "/usr/local/bin",
        "/tmp/parallax-deploy.",
    ] {
        payload = payload.replace(prefix, &format!("{}{prefix}", root.display()));
    }
    let upload = root.join("tmp/parallax-deploy.XXXXXX");
    let stage_upload = |config: &Path| {
        fs::create_dir_all(&upload).unwrap();
        fs::copy(env!("CARGO_BIN_EXE_plx"), upload.join("plx")).unwrap();
        fs::copy(config, upload.join("parallax.server.toml")).unwrap();
        fs::write(upload.join("parallax.service"), "[Service]\n").unwrap();
    };
    let old_path = fixture(root, "old.example");
    let new_path = fixture(root, "new.example");
    let old = Config::load(&old_path).unwrap();
    let expected = Config::load(&new_path).unwrap();
    assert_ne!(old.crypto.psk.as_b64(), expected.crypto.psk.as_b64());
    assert_ne!(
        old.server.as_ref().unwrap().authorized_sni,
        expected.server.as_ref().unwrap().authorized_sni
    );
    let active = root.join("etc/parallax/parallax.toml");
    stage_upload(&old_path);
    let initial = bash(&payload, root, false);
    assert!(initial.status.success(), "{:?}", initial);
    let old_sealed_text = fs::read_to_string(&active).unwrap();
    assert!(old_sealed_text.contains("sealed ="));
    assert_same_config(&Config::load(&active).unwrap(), &old);

    stage_upload(&new_path);
    let interrupted = bash(&payload, root, true);
    assert_eq!(interrupted.status.code(), Some(97), "{:?}", interrupted);
    // The new INLINE config was installed before sealing. Failure after the
    // bundle install cannot pair the old config's SNI with the new credentials.
    assert_eq!(
        fs::read_to_string(&active).unwrap(),
        fs::read_to_string(&new_path).unwrap()
    );
    assert_ne!(fs::read_to_string(&active).unwrap(), old_sealed_text);
    let current = Config::load(&active).unwrap();
    assert!(!current.inline_secret_fields().is_empty());
    assert_same_config(&current, &expected);

    stage_upload(&new_path);
    let completed = bash(&payload, root, false);
    assert!(completed.status.success(), "{:?}", completed);
    let current = Config::load(&active).unwrap();
    assert!(current.inline_secret_fields().is_empty());
    assert_same_config(&current, &expected);
    std::env::remove_var(parallax::secret_store::HOST_KEY_ENV);
}
