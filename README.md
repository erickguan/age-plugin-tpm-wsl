# age-plugin-tpm-wsl

An [age](https://age-encryption.org/) encryption plugin for **Windows Subsystem for Linux (WSL)** that uses your **Windows TPM 2.0** for decryption. Encrypt with a public recipient anywhere; decrypt on your Windows machine through the installed helper.

This personal project supports **age**, **rage**, and the **fnox secrets manager**, including encrypted local sync caches. It offers RSA-2048, P-256 HPKE, and MLKEM768-P256 hybrid **post-quantum encryption**.

## Requirements

- WSL with Windows interoperability enabled: Linux must be able to launch Windows `.exe` files.
- A Windows TPM 2.0 available to your Windows user through Microsoft Platform Crypto Provider.
- [age](https://github.com/FiloSottile/age) or [rage](https://github.com/str4d/rage) installed in WSL. Tested with age 1.3.2 and rage 0.12.1.
- Current stable Rust and a C/C++ compiler to build from source. The Windows cross-toolchain setup script uses Debian/Ubuntu package tooling.
- [fnox](https://fnox.jdx.dev/) if you want to use its age provider. Tested with fnox 1.42.1.

You do not need a Linux TPM device such as `/dev/tpmrm0`. The plugin uses the Windows TPM through WSL interoperability.

## Install

From this checkout, run:

```sh
sh scripts/setup-windows-toolchain.sh
sh scripts/install.sh
```

Make sure `~/.local/bin` is on your `PATH`:

```sh
export PATH="$HOME/.local/bin:$PATH"
age-plugin-tpm-wsl schemes
```

The installer builds a matched Linux plugin and Windows helper for your user. It creates the `age-plugin-tagpq` discovery alias and prepares the Windows folder permissions needed for key storage. Installation creates no TPM keys.

To update, run the installer again from the new checkout. Keep the plugin and helper from the same version; existing identities can be reused.

## Encrypt your first file

Create a new identity on the Windows machine where you will decrypt. This example chooses the post-quantum hybrid:

```sh
# Refuse to overwrite an existing identity file.
(
  set -euC
  umask 077
  age-plugin-tpm-wsl keygen --algorithm mlkem768-p256 > identity.txt
)

# Extract the public recipient, which you can share for encryption.
recipient=$(age-plugin-tpm-wsl recipient identity.txt)

printf 'hello from WSL\n' > message.txt
age --encrypt --recipient "$recipient" --output message.age message.txt
age --decrypt --identity identity.txt --output restored.txt message.age
```

You can use `rage` in place of `age`. Keep `identity.txt` so you can select the same Windows key for later reads. Encryption needs only the public recipient and works without access to Windows or the TPM. Decryption requires the original Windows user, TPM key and stored key data.

The identity file contains public information and a key reference. Copying that file alone does **not** back up the TPM key.

## Choose an algorithm

| Algorithm | Use |
| --- | --- |
| `rsa2048` | Default when `--algorithm` is omitted; retains compatibility with existing RSA identities. |
| `p256-hpke` | Classical encryption using P-256 HPKE. |
| `mlkem768-p256` | Hybrid ML-KEM-768 + P-256 encryption, using the standard `age1tagpq` recipient format. |

Select the algorithm when creating the identity. Existing identities keep their original algorithm. Use `age-plugin-tpm-wsl` for every management command; `age-plugin-tagpq` is an alias used by clients to discover tagged recipients.

## Use with fnox

Configure an age provider in your `fnox.toml`. Paste the output of `age-plugin-tpm-wsl recipient identity.txt` into `recipients`, and set `key_file` to your identity file's absolute path:

```toml
[providers.windows_tpm]
type = "age"
recipients = ["REPLACE_WITH_YOUR_AGE_RECIPIENT"]
key_file = "/absolute/path/to/identity.txt"
```

Then store and read a disposable example:

```sh
fnox --config fnox.toml --no-daemon set EXAMPLE_VALUE 'hello from WSL' --provider windows_tpm
fnox --config fnox.toml --no-daemon get EXAMPLE_VALUE
```

Use this provider with fnox's [encrypted sync cache](https://fnox.jdx.dev/guide/sync) when you need locally cached secrets. Direct reads, persistent-cache reads and isolated daemon cache reads have been tested. `--no-daemon` makes the example exercise decryption instead of a previously cached daemon value.

## Keep a recovery route

A lost TPM, cleared TPM, deleted key or lost Windows key storage can leave you unable to decrypt. For files you need to recover elsewhere, encrypt to an additional recipient whose identity you keep in a separate failure domain, such as another machine or an independently stored software identity.

The post-quantum walkthrough above requires a compatible **post-quantum recovery recipient**. Clients reject mixtures of classical and post-quantum recipients. Set `recovery_recipient` to your independently retained PQ recipient before running:

```sh
age --encrypt \
  --recipient "$recipient" \
  --recipient "$recovery_recipient" \
  --output backed-up.age message.txt
```

Either identity can decrypt this file. Test your recovery identity separately before relying on it; a second key on the same TPM does not protect against losing that TPM. Adding a recipient to future encryptions does not change existing ciphertext.

## Manage identities

| Command | What it does |
| --- | --- |
| `age-plugin-tpm-wsl schemes` | List supported algorithms without creating a key. |
| `age-plugin-tpm-wsl recipient identity.txt` | Print the shareable public recipient. |
| `age-plugin-tpm-wsl inspect identity.txt` | Inspect the referenced Windows key. |
| `age-plugin-tpm-wsl recover KEY_NAME` | Recreate a lost identity reference for an existing key. |
| `age-plugin-tpm-wsl delete identity.txt` | Delete the referenced key and verify absence. |

Key creation prints its Windows key name to stderr. If creation is interrupted, keep that name for inspection or explicit recovery. `recover` cannot restore a deleted TPM key. `delete` leaves local identity files and ciphertext on disk.

## Troubleshooting

- **Plugin not found:** put `~/.local/bin` on `PATH`. For `age1tagpq` recipients, check that `~/.local/bin/age-plugin-tagpq` exists; reinstall to restore the alias.
- **Windows helper cannot run:** confirm WSL interoperability works and inspect `~/.config/age-plugin-tpm-wsl/helper-path`. It must contain the helper's absolute Linux path. You can override it with `AGE_TPM_WSL_HELPER`.
- **Decryption times out:** the helper deadline defaults to ten seconds. `AGE_TPM_WSL_TIMEOUT` accepts 1–120 seconds. Check Windows availability and the referenced key before changing it.
- **Storage owner or ACL error:** rerun the current installer to apply the required Windows installation-folder permissions.
- **Key missing or TPM unavailable:** use the original Windows account and machine, or your independent recovery recipient. Decryption does not create replacement keys or fall back to software storage.

This plugin's identities are incompatible with [Foxboron's age-plugin-tpm](https://github.com/Foxboron/age-plugin-tpm). They use different key storage and recipient formats.

## Project status

The plugin is installed and tested on the author's machine, including age/rage files through 4 MiB, fnox reads, independent recovery decryption and decryption after a Windows reboot and WSL restart.

Build and install instructions are in this README. Validation evidence, design notes and agent working plans are kept outside this repository, so provenance records in `vendor/*.json` and `crates/*/source-origin.json` name the inputs they were checked against without publishing them.

## License

[Apache License, Version 2.0](LICENSE).
