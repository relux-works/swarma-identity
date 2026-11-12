//go:build linux

package facade

import "golang.org/x/sys/unix"

// exchangeAt atomically swaps the two names in dir with renameat2
// RENAME_EXCHANGE. A kernel or file system without it returns an error and
// changes nothing, and the caller then refuses to commit.
func exchangeAt(dir int, a, b string) error {
	_, err := retryEINTR(func() (int, error) { return 0, unix.Renameat2(dir, a, dir, b, unix.RENAME_EXCHANGE) })
	return err
}

// renameNewAt renames from to to in dir only while to does not exist, with
// renameat2 RENAME_NOREPLACE. Without it the caller refuses to commit.
func renameNewAt(dir int, from, to string) error {
	_, err := retryEINTR(func() (int, error) { return 0, unix.Renameat2(dir, from, dir, to, unix.RENAME_NOREPLACE) })
	return err
}
