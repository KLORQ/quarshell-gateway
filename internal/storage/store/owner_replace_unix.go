//go:build !windows

package store

import "os"

func replaceOwnerOnlyFile(source, destination string) error {
	return os.Rename(source, destination)
}
