//go:build windows

package download

import (
	"syscall"
	"unsafe"

	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/utils"
)

type callDiskFreeSpaceExW func(pathPtr *uint16, freeBytesAvailable *int64) (uintptr, error)

func CheckDiskSpace(log *logger.Logger, path string) (available uint64, err error) {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	getDiskFreeSpaceExW := kernel32.NewProc("GetDiskFreeSpaceExW")

	callDiskFreeSpaceExWImpl := func(pathPtr *uint16, freeBytesAvailable *int64) (uintptr, error) {
		callResult, _, callErr := getDiskFreeSpaceExW.Call(
			uintptr(unsafe.Pointer(pathPtr)),
			uintptr(unsafe.Pointer(freeBytesAvailable)),
			0,
			0,
		)
		return callResult, callErr
	}

	return checkDiskSpaceWindows(log, path, syscall.UTF16PtrFromString, callDiskFreeSpaceExWImpl)
}

func checkDiskSpaceWindows(
	log *logger.Logger,
	path string,
	utf16PtrFromString func(string) (*uint16, error),
	callDiskFreeSpaceExW callDiskFreeSpaceExW,
) (uint64, error) {
	var freeBytesAvailable int64

	pathPtr, err := utf16PtrFromString(path)
	if err != nil {
		log.Errorf("[CheckDiskSpace] UTF16PtrFromString error: %v", err)
		return 0, err
	}

	callResult, callErr := callDiskFreeSpaceExW(pathPtr, &freeBytesAvailable)
	if callResult == 0 {
		if callErr != nil && callErr != syscall.Errno(0) {
			log.Errorf("[CheckDiskSpace] callDiskFreeSpaceExW error: %v", callErr)
			return 0, callErr
		}
		log.Errorf("[CheckDiskSpace] callDiskFreeSpaceExW returned 0 with no error")
		return 0, syscall.EINVAL
	}

	hasRoot, err := utils.HasRoot()
	if err != nil {
		log.Errorf("[CheckDiskSpace] error checking for Administrator: %v", err)
	} else if hasRoot {
		log.Infof("[CheckDiskSpace] running as Administrator")
	} else {
		log.Infof("[CheckDiskSpace] running as non-Administrator")
	}

	log.Infof("[CheckDiskSpace] freeBytesAvailable: %d", freeBytesAvailable)
	return uint64(freeBytesAvailable), nil
}
