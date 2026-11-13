#!/bin/bash
# Build the release CLI in the Developer ID bundle verified at the owner's sitting.
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo 'Usage: .scripts/build-keychain-bundle.sh PROFILE [OUTPUT.app]' >&2
  exit 2
fi
if [[ $(uname -s) != Darwin ]]; then
  echo 'Developer ID bundle building requires macOS.' >&2
  exit 1
fi
profile=$1
bundle=${2:-.temp/SwarmaKeychain.app}
if [[ ! -f "$profile" || "$bundle" != *.app || -e "$bundle" || -L "$bundle" ]]; then
  echo 'Provide an existing provisioning profile and a new .app output path.' >&2
  exit 2
fi

mkdir -p "$bundle/Contents/MacOS"
cp "$profile" "$bundle/Contents/embedded.provisionprofile"
cat > "$bundle/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleIdentifier</key><string>works.relux.swarma-keychain</string>
  <key>CFBundleExecutable</key><string>swarma-keychain</string>
  <key>CFBundleName</key><string>SwarmaKeychain</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleVersion</key><string>1</string>
  <key>LSUIElement</key><true/>
</dict></plist>
PLIST
entitlements="${bundle%.app}.entitlements.plist"
# Refuse to replace an existing file, also a dangling symlink.
(set -C; cat > "$entitlements" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>com.apple.application-identifier</key><string>262RZ595FP.works.relux.swarma-keychain</string>
  <key>com.apple.developer.team-identifier</key><string>262RZ595FP</string>
  <key>keychain-access-groups</key><array><string>262RZ595FP.works.relux.swarma-keychain</string></array>
</dict></plist>
PLIST
)
# Run from the repository root. Ignore ambient build tags: never package keychaintest.
GOFLAGS= GOTOOLCHAIN=local CGO_ENABLED=1 go build -o "$bundle/Contents/MacOS/swarma-keychain" ./cmd/swarma-keychain
codesign --force --options runtime --entitlements "$entitlements" \
  --sign 'Developer ID Application: Relux Works, LLC (262RZ595FP)' "$bundle"
codesign --verify --strict "$bundle"
printf 'Signed bundle: %s\n' "$bundle"
