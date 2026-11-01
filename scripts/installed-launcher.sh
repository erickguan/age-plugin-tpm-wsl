#!/bin/sh
# Launch the installed plugin with this machine's absolute helper path.
set -eu
if [ -z "${AGE_TPM_WSL_HELPER+x}" ]; then
    IFS= read -r AGE_TPM_WSL_HELPER < "$HOME/.config/age-plugin-tpm-wsl/helper-path"
    export AGE_TPM_WSL_HELPER
fi
exec "$HOME/.local/lib/age-plugin-tpm-wsl/age-plugin-tpm-wsl" "$@"
