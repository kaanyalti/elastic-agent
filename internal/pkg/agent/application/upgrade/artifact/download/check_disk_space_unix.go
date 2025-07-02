//go:build !windows

package download

import (
	"syscall"

	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/utils"
)

// CheckDiskSpace returns the available bytes on the filesystem containing the given path.
// It uses syscall.Statfs and is implemented for Unix-like systems (Linux, macOS).
// If the process has root privileges, it returns all free space (including reserved blocks).
// Otherwise, it returns only the space available to unprivileged users.
func CheckDiskSpace(log *logger.Logger, path string) (available uint64, err error) {
	log.Infof("[CheckDiskSpace] Checking disk space for path: %s", path)
	available, err = checkDiskSpaceUnix(log, path, syscall.Statfs, utils.HasRoot)
	if err != nil {
		log.Errorf("[CheckDiskSpace] Error checking disk space: %v", err)
	} else {
		log.Infof("[CheckDiskSpace] Available bytes: %d", available)
	}
	return available, err
}

// Private function for testability
func checkDiskSpaceUnix(
	log *logger.Logger,
	path string,
	statfs func(string, *syscall.Statfs_t) error,
	hasRootFunc func() (bool, error),
) (uint64, error) {
	log.Infof("[checkDiskSpaceUnix] Called with path: %s", path)
	var stat syscall.Statfs_t
	if err := statfs(path, &stat); err != nil {
		log.Errorf("[checkDiskSpaceUnix] statfs error: %v", err)
		return 0, err
	}
	log.Infof("[checkDiskSpaceUnix] statfs result: Bsize=%d, Blocks=%d, Bfree=%d, Bavail=%d", stat.Bsize, stat.Blocks, stat.Bfree, stat.Bavail)
	hasRoot, err := hasRootFunc()
	if err != nil {
		log.Errorf("[checkDiskSpaceUnix] hasRootFunc error: %v", err)
		return 0, err
	}
	log.Infof("[checkDiskSpaceUnix] hasRoot: %v", hasRoot)
	if hasRoot {
		available := stat.Bfree * uint64(stat.Bsize)
		log.Infof("[checkDiskSpaceUnix] Returning all free space (root): %d bytes", available)
		return available, nil
	}
	available := stat.Bavail * uint64(stat.Bsize)
	log.Infof("[checkDiskSpaceUnix] Returning available space (unprivileged): %d bytes", available)
	return available, nil
}
