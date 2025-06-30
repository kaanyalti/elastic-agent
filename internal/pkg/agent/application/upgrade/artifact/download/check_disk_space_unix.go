//go:build !windows

package download

import (
	"syscall"

	"github.com/elastic/elastic-agent/pkg/utils"
)

// CheckDiskSpace returns the available and total bytes on the filesystem containing the given path.
// It uses syscall.Statfs and is implemented for Unix-like systems (Linux, macOS).
// If the process has root privileges, it returns all free space (including reserved blocks).
// Otherwise, it returns only the space available to unprivileged users.
func CheckDiskSpace(path string) (available uint64, total uint64, err error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return 0, 0, err
	}

	hasRoot, err := utils.HasRoot()
	if err != nil {
		return 0, 0, err
	}
	if hasRoot {
		available = stat.Bfree * uint64(stat.Bsize)
	} else {
		available = stat.Bavail * uint64(stat.Bsize)
	}
	total = stat.Blocks * uint64(stat.Bsize)
	return available, total, nil
}
