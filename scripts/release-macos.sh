#!/usr/bin/env bash
# Build and verify only. Publication is a separate, gated workflow step.
set +x
set -euo pipefail
umask 077
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
CHECKS="$ROOT/scripts/release_checks.py"
MACOS="$ROOT/release/macos"
REQ="$MACOS/DESIGNATED-REQUIREMENT.txt"
ENT="$MACOS/swarma-keychain.entitlements.plist"
fail() { printf 'release gate: %s\n' "$*" >&2; exit 1; }

# No tool invocation that consumes signing material precedes this gate.
python3 "$CHECKS" secrets
python3 "$CHECKS" pins
[[ "$(uname -s)" == Darwin ]] || fail 'signing and notarization require macOS'
[[ "${GITHUB_REF_TYPE:-}" == tag && "${GITHUB_REF:-}" == refs/tags/v* ]] || fail 'only pushed v* tags may release'
[[ "${GITHUB_REF_NAME:-}" =~ ^v[0-9][0-9A-Za-z.+-]*$ ]] || fail 'unsafe or invalid release tag'
[[ "$(git rev-parse HEAD)" == "$(git rev-parse "${GITHUB_REF}^{commit}")" ]] || fail 'checkout does not match the tag'
[[ "$(git rev-parse HEAD)" == "$GITHUB_SHA" ]] || fail 'checkout does not match the event commit'
for tool in security codesign xcrun spctl ditto go python3 shasum tar; do
  command -v "$tool" >/dev/null || fail "missing tool: $tool"
done
xcrun --find notarytool >/dev/null
xcrun --find stapler >/dev/null

work="$(mktemp -d "$RUNNER_TEMP/swarma-release.XXXXXX")"
keychain="$work/release.keychain-db"
cleanup() {
  status=$?
  trap - EXIT
  if SWARMA_RELEASE_WORK="$work" SWARMA_RELEASE_KEYCHAIN="$keychain" bash "$ROOT/scripts/release-cleanup.sh"; then
    :
  else
    # Cleanup cannot turn an earlier gate failure into success or replace its
    # exit code. When signing succeeded, cleanup failure becomes the failure.
    cleanup_status=$?
    if [[ "$status" == 0 ]]; then status="$cleanup_status"; fi
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
# Persist only recovery paths, before any credentials or keychain are created.
# The workflow runner consumes this file even if this process cannot run EXIT.
printf 'SWARMA_RELEASE_WORK=%s\nSWARMA_RELEASE_KEYCHAIN=%s\n' \
  "$work" "$keychain" >> "$GITHUB_ENV"
python3 "$CHECKS" prepare-secrets "$work"
keychain_password="$(cat "$work/keychain-password")"
issuer="$ASC_ISSUER_ID"
key_id="$ASC_KEY_ID"
security create-keychain -p "$keychain_password" "$keychain"
security set-keychain-settings -lut 21600 "$keychain"
security unlock-keychain -p "$keychain_password" "$keychain"
# Save non-secret user paths before prepending this keychain for codesign.
python3 "$ROOT/scripts/release_keychains.py" configure "$work" "$keychain"
security import "$work/certificate.p12" -k "$keychain" -P "$MACOS_SIGN_P12_PASSWORD" -T /usr/bin/codesign > "$work/import.log" 2>&1
security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$keychain_password" "$keychain" > "$work/partition.log" 2>&1
rm "$work/certificate.p12" "$work/keychain-password"
unset MACOS_SIGN_P12 MACOS_SIGN_P12_PASSWORD ASC_KEY_P8 ASC_ISSUER_ID ASC_KEY_ID keychain_password
security find-identity -v -p codesigning "$keychain" > "$work/identities.txt"
identity="$(python3 "$CHECKS" identity "$work/identities.txt")"

# Release flags cannot inherit test tags or select a non-native Keychain backend.
export GOFLAGS= GOTOOLCHAIN=local GOMAXPROCS=2
unset SWARMA_KEYCHAIN_TEST_PATH GOOS GOARCH
APP="$work/SwarmaKeychain.app"
CGO_ENABLED=1 go run ./cmd/build-keychain-bundle --build-only "$MACOS/swarma-keychain_DevID.provisionprofile" "$APP"
python3 "$CHECKS" entitlements "$ENT" "$work/SwarmaKeychain.entitlements.plist"
cmp "$MACOS/swarma-keychain_DevID.provisionprofile" "$APP/Contents/embedded.provisionprofile"

# The existing builder has exactly one inner executable. Sign it first; never
# use --deep for signing. Give the executable and bundle the same fixed DR.
for target in "$APP/Contents/MacOS/swarma-keychain" "$APP"; do
  codesign --force --keychain "$keychain" --sign "$identity" --identifier works.relux.swarma-keychain \
    --options runtime --timestamp --entitlements "$ENT" --requirements "$REQ" "$target"
done
codesign --verify --strict --deep "$APP"

# A real signed, not-yet-stapled app is the missing-ticket negative control.
# An unrelated failure (missing tool, invalid signature, etc.) is not a pass.
if xcrun stapler validate "$APP" > "$work/no-ticket.log" 2>&1; then
  fail 'missing-ticket negative control unexpectedly accepted an unstapled app'
else
  ticket_status=$?
  grep -F 'does not have a ticket stapled' "$work/no-ticket.log" >/dev/null || fail 'missing-ticket control failed for an unrelated reason'
fi
printf 'Missing-ticket negative control passed (stapler exit %s).\n' "$ticket_status"

notarize() {
  local archive="$1" response="$2"
  xcrun notarytool submit "$archive" --wait --timeout 30m \
    --key "$work/AuthKey.p8" --key-id "$key_id" --issuer "$issuer" --output-format json > "$response"
  python3 "$CHECKS" notary "$response"
}
verify_app() {
  local app="$1"
  # Stapler checks the local ticket even when Gatekeeper could query Apple.
  xcrun stapler validate "$app"
  codesign --verify --strict --deep "$app"
  spctl -a -t exec -vv "$app" > "$work/assessment.txt" 2>&1
  python3 "$CHECKS" assessment "$work/assessment.txt"
  codesign -d -r- "$app" > "$work/requirement.txt" 2> "$work/requirement-diagnostic.txt"
  python3 "$CHECKS" requirement "$REQ" "$work/requirement.txt"
  codesign -d --entitlements :- "$app" > "$work/entitlements.plist" 2> "$work/entitlements-diagnostic.txt"
  python3 "$CHECKS" entitlements "$ENT" "$work/entitlements.plist"
  # The inner executable must carry the same entitlements and requirement.
  codesign -d -r- "$app/Contents/MacOS/swarma-keychain" > "$work/inner-requirement.txt" 2> "$work/inner-requirement-diagnostic.txt"
  python3 "$CHECKS" requirement "$REQ" "$work/inner-requirement.txt"
  codesign -d --entitlements :- "$app/Contents/MacOS/swarma-keychain" > "$work/inner-entitlements.plist" 2> "$work/inner-entitlements-diagnostic.txt"
  python3 "$CHECKS" entitlements "$ENT" "$work/inner-entitlements.plist"
  cmp "$MACOS/swarma-keychain_DevID.provisionprofile" "$app/Contents/embedded.provisionprofile"
}

ditto -c -k --keepParent "$APP" "$work/app-submit.zip"
notarize "$work/app-submit.zip" "$work/app-notary.json"
xcrun stapler staple "$APP"
verify_app "$APP"
python3 "$CHECKS" controls "$REQ" "$work/requirement.txt" "$ENT" "$work/entitlements.plist"

# Dist must be new. Only explicitly selected final assets can be published.
mkdir "$ROOT/dist"
version="$GITHUB_REF_NAME"
app_arch="$(go env GOARCH)"
app_zip="$ROOT/dist/SwarmaKeychain_${version}_darwin_${app_arch}.zip"
ditto -c -k --keepParent "$APP" "$app_zip"
# Validate the actual distribution archive after round trip (ticket included).
mkdir "$work/unpacked"
ditto -x -k "$app_zip" "$work/unpacked"
verify_app "$work/unpacked/SwarmaKeychain.app"
cp "$work/requirement.txt" "$ROOT/dist/DESIGNATED-REQUIREMENT.txt"

for os in darwin linux; do
  for arch in amd64 arm64; do
    name="swarma-identity_${version}_${os}_${arch}"
    stage="$work/$name"
    mkdir "$stage"
    CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -p 1 -trimpath -ldflags='-s -w' -o "$stage/swarma-identity" ./cmd/swarma-identity
    cp LICENSE NOTICE README.md "$stage/"
    if [[ "$os" == darwin ]]; then
      codesign --force --keychain "$keychain" --sign "$identity" --identifier works.relux.swarma-identity \
        --options runtime --timestamp "$stage/swarma-identity"
      codesign --verify --strict "$stage/swarma-identity"
      ditto -c -k --keepParent "$stage" "$work/$name.zip"
      notarize "$work/$name.zip" "$work/$name-notary.json"
      # Apple does not support stapling standalone Mach-O executables. Their
      # Accepted submissions register the binary tickets with Apple's service.
    fi
    tar -czf "$ROOT/dist/$name.tar.gz" -C "$stage" swarma-identity LICENSE NOTICE README.md
  done
done
(
  cd "$ROOT/dist"
  shasum -a 256 ./*.zip ./*.tar.gz DESIGNATED-REQUIREMENT.txt > SHA256SUMS
  shasum -a 256 -c SHA256SUMS
)
# The EXIT trap is defense in depth; the independent workflow cleanup step
# must also succeed before publication. No success marker overrides either gate.
