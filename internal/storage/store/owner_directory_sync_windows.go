//go:build windows

package store

// Windows does not expose directory fsync through os.File.Sync. The replacement
// itself uses MoveFileEx with MOVEFILE_WRITE_THROUGH instead.
func syncOwnerOnlyDirectory(string) error { return nil }
