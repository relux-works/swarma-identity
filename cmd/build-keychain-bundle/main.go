// build-keychain-bundle builds the release signer in the Developer ID bundle
// verified at the owner's sitting. Run it from the repository root on macOS.
package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

type options struct{ profile, bundle string }
type command struct {
	name string
	args []string
	env  []string
}

func arguments(args []string) (options, error) {
	if len(args) < 1 || len(args) > 2 {
		return options{}, errors.New("Usage: go run ./cmd/build-keychain-bundle PROFILE [OUTPUT.app]")
	}
	o := options{args[0], ".temp/SwarmaKeychain.app"}
	if len(args) == 2 {
		o.bundle = args[1]
	}
	return o, nil
}

func main() {
	os.Exit(run(os.Args[1:], runtime.GOOS, os.Stdout, os.Stderr, func(c command) error {
		cmd := exec.Command(c.name, c.args...)
		cmd.Env, cmd.Stdin, cmd.Stdout, cmd.Stderr = c.env, os.Stdin, os.Stdout, os.Stderr
		return cmd.Run()
	}))
}

func run(args []string, platform string, stdout, stderr io.Writer, execute func(command) error) int {
	o, err := arguments(args)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if platform != "darwin" {
		fmt.Fprintln(stderr, "Developer ID bundle building requires macOS.")
		return 1
	}
	profile, err := os.Stat(o.profile)
	if err != nil || !profile.Mode().IsRegular() || !strings.HasSuffix(o.bundle, ".app") || !absent(o.bundle) {
		fmt.Fprintln(stderr, "Provide an existing provisioning profile and a new .app output path.")
		return 2
	}
	entitlements := strings.TrimSuffix(o.bundle, ".app") + ".entitlements.plist"
	if err := createBundle(o, profile.Mode().Perm(), entitlements); err != nil {
		fmt.Fprintf(stderr, "Could not create bundle: %v\n", err)
		return 1
	}
	commands := []command{
		{"go", []string{"build", "-o", filepath.Join(o.bundle, "Contents/MacOS/swarma-keychain"), "./cmd/swarma-keychain"}, releaseEnvironment()},
		{"codesign", []string{"--force", "--options", "runtime", "--entitlements", entitlements, "--sign", "Developer ID Application: Relux Works, LLC (262RZ595FP)", o.bundle}, nil},
		{"codesign", []string{"--verify", "--strict", o.bundle}, nil},
	}
	for _, c := range commands {
		if err := execute(c); err != nil {
			fmt.Fprintf(stderr, "%s failed: %v\n", c.name, err)
			var exit interface{ ExitCode() int }
			if errors.As(err, &exit) && exit.ExitCode() > 0 {
				return exit.ExitCode()
			}
			if errors.Is(err, exec.ErrNotFound) {
				return 127
			}
			return 1
		}
	}
	fmt.Fprintf(stdout, "Signed bundle: %s\n", o.bundle)
	return 0
}

func absent(path string) bool {
	_, err := os.Lstat(path) // a dangling symlink is also an existing output
	return os.IsNotExist(err)
}

func createBundle(o options, profileMode os.FileMode, entitlements string) error {
	profile, err := os.ReadFile(o.profile)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(o.bundle), 0755); err != nil {
		return err
	}
	if err := os.Mkdir(o.bundle, 0755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(o.bundle, "Contents/MacOS"), 0755); err != nil {
		return err
	}
	for _, file := range []struct {
		path string
		data []byte
		mode os.FileMode
	}{
		{filepath.Join(o.bundle, "Contents/embedded.provisionprofile"), profile, profileMode},
		{filepath.Join(o.bundle, "Contents/Info.plist"), []byte(infoPlist), 0644},
		{entitlements, []byte(entitlementsPlist), 0644},
	} {
		if err := writeNew(file.path, file.data, file.mode); err != nil {
			return err
		}
	}
	return nil
}

func writeNew(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	closeErr := f.Close()
	return errors.Join(err, closeErr)
}

func releaseEnvironment() []string {
	env := make([]string, 0, len(os.Environ())+3)
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if key != "GOFLAGS" && key != "GOTOOLCHAIN" && key != "CGO_ENABLED" {
			env = append(env, entry)
		}
	}
	// Never package inherited keychaintest tags; always build the native release.
	return append(env, "GOFLAGS=", "GOTOOLCHAIN=local", "CGO_ENABLED=1")
}

const infoPlist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleIdentifier</key><string>works.relux.swarma-keychain</string>
  <key>CFBundleExecutable</key><string>swarma-keychain</string>
  <key>CFBundleName</key><string>SwarmaKeychain</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleVersion</key><string>1</string>
  <key>LSUIElement</key><true/>
</dict></plist>
`

const entitlementsPlist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>com.apple.application-identifier</key><string>262RZ595FP.works.relux.swarma-keychain</string>
  <key>com.apple.developer.team-identifier</key><string>262RZ595FP</string>
  <key>keychain-access-groups</key><array><string>262RZ595FP.works.relux.swarma-keychain</string></array>
</dict></plist>
`
