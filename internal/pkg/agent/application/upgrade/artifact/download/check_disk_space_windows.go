//go:build windows

package download

import (
	"fmt"
	"syscall"
	"unsafe"

	"github.com/elastic/elastic-agent/pkg/utils"
)

// CheckDiskSpace returns the available and total bytes on the filesystem containing the given path.
// It uses the Windows API GetDiskFreeSpaceEx and is implemented for Windows only.
// Only the free space available to the calling user is returned (not all free space).
// TODO: This is temporary to see if for unprivileged agent the apparent user is in fact the unprivileged elastic-agent-user. Remove it later
func CheckDiskSpace(path string) (available uint64, total uint64, err error) {
	var (
		freeBytesAvailable int64
		totalNumberOfBytes int64
	)
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	getDiskFreeSpaceExW := kernel32.NewProc("GetDiskFreeSpaceExW")

	// Convert path to UTF-16
	pathPtr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, 0, err
	}

	r1, _, callErr := getDiskFreeSpaceExW.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		uintptr(unsafe.Pointer(&freeBytesAvailable)),
		uintptr(unsafe.Pointer(&totalNumberOfBytes)),
		0, // We do not need totalNumberOfFreeBytes
	)
	if r1 == 0 {
		if callErr != nil && callErr != syscall.Errno(0) {
			return 0, 0, callErr
		}
		return 0, 0, syscall.EINVAL
	}

	hasRoot, err := utils.HasRoot()
	if err != nil {
		fmt.Printf("[CheckDiskSpace] error checking for Administrator: %v\n", err)
	} else if hasRoot {
		fmt.Printf("[CheckDiskSpace] running as Administrator\n")
	} else {
		fmt.Printf("[CheckDiskSpace] running as non-Administrator\n")
	}

	return uint64(freeBytesAvailable), uint64(totalNumberOfBytes), nil
}
