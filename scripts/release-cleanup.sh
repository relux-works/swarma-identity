#!/usr/bin/env bash
# Independent, idempotent cleanup shared by the process trap and always() step.
set +x
set -euo pipefail
work="${SWARMA_RELEASE_WORK:-}"
keychain="${SWARMA_RELEASE_KEYCHAIN:-}"
fail() { printf 'release cleanup: %s\n' "$*" >&2; exit 1; }

# Signing may have failed before allocating private storage.
if [[ -z "$work" && -z "$keychain" ]]; then exit 0; fi
[[ -n "$work" && -n "$keychain" && -n "${RUNNER_TEMP:-}" ]] || fail 'incomplete recovery paths'
[[ "${work%/*}" == "${RUNNER_TEMP%/}" && "${work##*/}" == swarma-release.?* && "$keychain" == "$work/release.keychain-db" ]] || fail 'recovery paths are outside this release workspace'
[[ ! -L "$work" && ! -L "$keychain" ]] || fail 'recovery paths must not be symlinks'
[[ ! -e "$work" || -d "$work" ]] || fail 'private workspace is not a directory'
[[ ! -e "$keychain" || -f "$keychain" ]] || fail 'keychain is not a regular file'

# Restore before deletion in BOTH the process trap and independent always step.
# On failure retain the non-secret recovery state and keychain for a retry,
# while removing loose credentials. Never publish after failed restoration.
if python3 "$(dirname "$0")/release_keychains.py" restore "$work"; then
  :
else
  rm -f "$work/AuthKey.p8" "$work/certificate.p12" "$work/keychain-password"
  fail 'original user keychain state restoration failed; recovery state retained'
fi

status=0
if [[ -f "$keychain" ]]; then
  if security delete-keychain "$keychain" >/dev/null 2>&1; then
    :
  else
    printf 'release cleanup: temporary keychain deletion failed\n' >&2
    status=1
  fi
fi
# Attempt file removal even if native keychain deletion failed. Still return a
# failure so publication cannot treat native deletion as successfully verified.
if [[ -d "$work" ]]; then
  if rm -rf "$work"; then
    :
  else
    printf 'release cleanup: private workspace removal failed\n' >&2
    status=1
  fi
fi
if [[ -e "$work" ]]; then
  printf 'release cleanup: signing files remain in the private workspace\n' >&2
  status=1
fi
exit "$status"
