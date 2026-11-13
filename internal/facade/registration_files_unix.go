//go:build linux || darwin

package facade

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

type regDirectory struct {
	fd, parent int
	name       string
}
type regHeldPath struct {
	dirs []regDirectory
	leaf string
}

func regAbs(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && path != "/" && !strings.ContainsRune(path, 0)
}
func regDirSafe(fd int) bool {
	var st unix.Stat_t
	return unix.Fstat(fd, &st) == nil && st.Mode&unix.S_IFMT == unix.S_IFDIR && (st.Uid == 0 || st.Uid == uint32(os.Geteuid())) && st.Mode&07022 == 0
}
func regWalk(path string) (*regHeldPath, *Failure) {
	if !regAbs(path) || os.Getuid() != os.Geteuid() {
		return nil, regFailure("REGISTRATION_FILES")
	}
	h := &regHeldPath{leaf: filepath.Base(path)}
	fd, e := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, regFailure("REGISTRATION_FILES")
	}
	h.dirs = append(h.dirs, regDirectory{fd: fd, parent: -1})
	for _, part := range strings.Split(strings.TrimPrefix(filepath.Dir(path), "/"), "/") {
		if part == "" {
			continue
		}
		next, e := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if e != nil {
			h.close()
			return nil, regFailure("REGISTRATION_FILES")
		}
		h.dirs = append(h.dirs, regDirectory{next, fd, part})
		fd = next
	}
	if !h.valid() {
		h.close()
		return nil, regFailure("REGISTRATION_FILES")
	}
	return h, nil
}
func (h *regHeldPath) parent() int { return h.dirs[len(h.dirs)-1].fd }
func (h *regHeldPath) close() {
	for i := len(h.dirs) - 1; i >= 0; i-- {
		unix.Close(h.dirs[i].fd)
	}
	h.dirs = nil
}
func (h *regHeldPath) valid() bool {
	for _, d := range h.dirs {
		if !regDirSafe(d.fd) {
			return false
		}
		if d.parent >= 0 {
			var a, b unix.Stat_t
			if unix.Fstatat(d.parent, d.name, &a, unix.AT_SYMLINK_NOFOLLOW) != nil || unix.Fstat(d.fd, &b) != nil || a.Dev != b.Dev || a.Ino != b.Ino || a.Mode&unix.S_IFMT != unix.S_IFDIR {
				return false
			}
		}
	}
	return len(h.dirs) > 0
}
func regFileStatSafe(st unix.Stat_t) bool {
	return st.Mode&unix.S_IFMT == unix.S_IFREG && st.Mode&07777 == 0600 && st.Uid == uint32(os.Geteuid()) && st.Nlink == 1
}

func (h *regHeldPath) check(f *os.File) (unix.Stat_t, time.Time, bool) {
	var a, b unix.Stat_t
	if !h.valid() || unix.Fstat(int(f.Fd()), &a) != nil || !regFileStatSafe(a) || unix.Fstatat(h.parent(), h.leaf, &b, unix.AT_SYMLINK_NOFOLLOW) != nil || a.Dev != b.Dev || a.Ino != b.Ino || b.Mode&unix.S_IFMT != unix.S_IFREG {
		return a, time.Time{}, false
	}
	info, e := f.Stat()
	if e != nil {
		return a, time.Time{}, false
	}
	return a, info.ModTime(), true
}

type regFrozen struct {
	raw                  []byte
	hash, expected, role string
	size                 int64
	dev, ino             uint64
	mod                  time.Time
}
type regFreezer struct {
	files  map[string]*regFrozen
	inodes map[[2]uint64]string
	total  uint64
}

func newRegFreezer() *regFreezer {
	return &regFreezer{files: map[string]*regFrozen{}, inodes: map[[2]uint64]string{}}
}
func (z *regFreezer) read(path string, cap int, expected, role string, selectedProfile ...bool) ([]byte, *Failure) {
	h, failure := regWalk(path)
	if failure != nil {
		return nil, failure
	}
	defer h.close()
	fd, e := unix.Openat(h.parent(), h.leaf, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, regFailure("REGISTRATION_FILES")
	}
	f := os.NewFile(uintptr(fd), "registration input")
	defer f.Close()
	st, mod, ok := h.check(f)
	if !ok || st.Size < 0 || st.Size > int64(cap) {
		return nil, regFailure("REGISTRATION_FILES")
	}
	key := [2]uint64{uint64(st.Dev), st.Ino}
	if old := z.files[path]; old != nil {
		if old.expected != expected || old.role != role || old.dev != key[0] || old.ino != key[1] || old.size != st.Size || !old.mod.Equal(mod) {
			return nil, regFailure("REGISTRATION_FILES")
		}
		return old.raw, nil
	}
	if _, seen := z.inodes[key]; seen || len(z.files) >= 128 || uint64(st.Size) > 128<<20-z.total {
		return nil, regFailure("REGISTRATION_FILES")
	}
	raw := make([]byte, int(st.Size))
	if len(raw) > 0 {
		n, e := f.ReadAt(raw, 0)
		if e != nil || n != len(raw) {
			return nil, regFailure("REGISTRATION_FILES")
		}
	}
	var extra [1]byte
	n, e := f.ReadAt(extra[:], st.Size)
	if n != 0 || e != io.EOF {
		return nil, regFailure("REGISTRATION_FILES")
	}
	after, afterMod, ok := h.check(f)
	if !ok || st.Dev != after.Dev || st.Ino != after.Ino || st.Size != after.Size || !mod.Equal(afterMod) {
		return nil, regFailure("REGISTRATION_FILES")
	}
	hash := regDigest(raw)
	if expected != "" && expected != hash {
		code := "REGISTRATION_FILES"
		if len(selectedProfile) > 0 && selectedProfile[0] {
			code = "REGISTRATION_POLICY_REFUSED"
		}
		return nil, regFailure(code)
	}
	z.files[path] = &regFrozen{raw, hash, expected, role, st.Size, key[0], key[1], mod}
	z.inodes[key] = path
	z.total += uint64(st.Size)
	return raw, nil
}
func regHoldBundle(indexPath string) (*regHeldPath, *Failure) {
	h, f := regWalk(indexPath)
	if f != nil {
		return nil, f
	}
	if !regSourceDirectorySafe(h) {
		h.close()
		return nil, regFailure("REGISTRATION_FILES")
	}
	return h, nil
}
func regSourceDirectorySafe(h *regHeldPath) bool {
	var st unix.Stat_t
	return h.valid() && unix.Fstat(h.parent(), &st) == nil && st.Uid == uint32(os.Geteuid()) && st.Mode&07777 == 0700
}

// regCommit writes payloads create-only, syncs and verifies each through its
// held path, commits the index last, then syncs the directory. Any interruption
// preserves leftovers; no call repairs or resumes an existing directory.
func regCommit(ctx context.Context, path, kind, profileHash, pinHash string, payload map[string][]byte) (*regSuccess, *Failure) {
	names := regPayloads[kind]
	if len(names) == 0 || len(names) != len(payload) {
		return nil, regFailure("INTERNAL")
	}
	index := regBundle{regPrefix + "bundle/1", kind, profileHash, pinHash, []regFile{}}
	for _, name := range names {
		b, ok := payload[name]
		if !ok || len(b) > regCap(name) {
			return nil, regFailure("REGISTRATION_FILES")
		}
		index.Files = append(index.Files, regFile{name, uint64(len(b)), regDigest(b)})
	}
	rawIndex := regCanonical(index)
	if len(rawIndex) > 65536 {
		return nil, regFailure("REGISTRATION_FILES")
	}
	if ctx.Err() != nil {
		return nil, regFailure("REGISTRATION_FILES")
	}
	h, failure := regWalk(path)
	if failure != nil {
		return nil, failure
	}
	defer h.close()
	if unix.Mkdirat(h.parent(), h.leaf, 0700) != nil {
		return nil, regFailure("REGISTRATION_FILES")
	}
	fd, e := unix.Openat(h.parent(), h.leaf, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, regFailure("REGISTRATION_FILES")
	}
	defer unix.Close(fd)
	validDir := func() bool {
		var a, b unix.Stat_t
		return h.valid() && unix.Fstat(fd, &a) == nil && a.Uid == uint32(os.Geteuid()) && a.Mode&07777 == 0700 && unix.Fstatat(h.parent(), h.leaf, &b, unix.AT_SYMLINK_NOFOLLOW) == nil && a.Ino == b.Ino && a.Dev == b.Dev
	}
	if !validDir() || unix.Fsync(h.parent()) != nil {
		return nil, regFailure("REGISTRATION_FILES")
	}
	write := func(name string, b []byte) bool {
		if ctx.Err() != nil || !validDir() {
			return false
		}
		n, e := unix.Openat(fd, name, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
		if e != nil {
			return false
		}
		file := os.NewFile(uintptr(n), "registration output")
		defer file.Close()
		written, e := file.Write(b)
		if e != nil || written != len(b) || file.Sync() != nil {
			return false
		}
		held, f := regWalk(filepath.Join(path, name))
		if f != nil {
			return false
		}
		defer held.close()
		before, mod, ok := held.check(file)
		if !ok || before.Size != int64(len(b)) {
			return false
		}
		check := make([]byte, len(b))
		if len(check) > 0 {
			n, e := file.ReadAt(check, 0)
			if e != nil || n != len(check) {
				return false
			}
		}
		after, afterMod, ok := held.check(file)
		good := ok && before.Size == after.Size && mod.Equal(afterMod) && bytes.Equal(check, b) && validDir()
		return file.Close() == nil && good
	}
	for _, name := range names {
		if !write(name, payload[name]) {
			return nil, regFailure("REGISTRATION_FILES")
		}
	}
	if !write("bundle.json", rawIndex) || unix.Fsync(fd) != nil || ctx.Err() != nil || !validDir() {
		return nil, regFailure("REGISTRATION_FILES")
	}
	return &regSuccess{regDigest(rawIndex), index.Files}, nil
}
