//go:build darwin

package facade

import "golang.org/x/sys/unix"

// exchangeAt atomically swaps the two names in dir with renameatx_np
// RENAME_SWAP. A file system without it returns an error and changes
// nothing, and the caller then refuses to commit.
func exchangeAt(dir int, a, b string) error {
	_, err := retryEINTR(func() (int, error) { return 0, unix.RenameatxNp(dir, a, dir, b, unix.RENAME_SWAP) })
	return err
}

// renameNewAt renames from to to in dir only while to does not exist, with
// renameatx_np RENAME_EXCL. Without it the caller refuses to commit.
func renameNewAt(dir int, from, to string) error {
	_, err := retryEINTR(func() (int, error) { return 0, unix.RenameatxNp(dir, from, dir, to, unix.RENAME_EXCL) })
	return err
}
