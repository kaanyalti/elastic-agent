//go:build windows

package download

import (
	"errors"
	"syscall"
	"testing"

	"github.com/elastic/elastic-agent/pkg/core/logger"
)

type diskProps struct {
	freeBytesAvailable int64
	apiErr             error
	apiReturnZero      bool
}

type testCase struct {
	disk        diskProps
	expectAvail uint64
	expectErr   bool
}

func apiProvider(freeBytesAvailable int64, apiErr error, returnZero bool) callDiskFreeSpaceExW {
	return func(_ *uint16, ptr *int64) (uintptr, error) {
		*ptr = freeBytesAvailable
		if returnZero {
			return 0, apiErr
		}
		return 1, apiErr
	}
}

func mockUTF16PtrFromString(_ string) (*uint16, error) {
	var dummy uint16 // using this to avoid the need to import unsafe
	return &dummy, nil
}

func mockUTF16PtrFromStringErr(_ string) (*uint16, error) {
	return nil, errors.New("utf16 error")
}

func TestCheckDiskSpaceWindows(t *testing.T) {
	tests := map[string]testCase{
		"success, returns available space": {
			disk:        diskProps{freeBytesAvailable: 12345, apiErr: nil, apiReturnZero: false},
			expectAvail: 12345,
			expectErr:   false,
		},
		"api error and callResult is zero, returns error": {
			disk:        diskProps{freeBytesAvailable: 0, apiErr: errors.New("api error"), apiReturnZero: true},
			expectAvail: 0,
			expectErr:   true,
		},
		"api error but callResult is non-zero, ignores error": {
			disk:        diskProps{freeBytesAvailable: 0, apiErr: errors.New("api error"), apiReturnZero: false},
			expectAvail: 0,
			expectErr:   false,
		},
		"invalid path, returns error": {
			disk:        diskProps{freeBytesAvailable: 0, apiErr: syscall.ENOENT, apiReturnZero: true},
			expectAvail: 0,
			expectErr:   true,
		},
		"UTF16 conversion error, returns error": {
			disk:        diskProps{freeBytesAvailable: 0, apiErr: nil, apiReturnZero: false},
			expectAvail: 0,
			expectErr:   true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			utf16Func := mockUTF16PtrFromString

			if name == "UTF16 conversion error" {
				utf16Func = mockUTF16PtrFromStringErr
			}

			// Use a dummy logger for testing
			var testLogger *logger.Logger = nil
			available, err := checkDiskSpaceWindows(
				testLogger,
				"C:\\mockPath",
				utf16Func,
				apiProvider(tc.disk.freeBytesAvailable, tc.disk.apiErr, tc.disk.apiReturnZero),
			)

			if tc.expectErr {
				if err == nil {
					t.Errorf("expected error, got nil")
				}

				if available != 0 {
					t.Errorf("expected 0, got %d", available)
				}

				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			if available != tc.expectAvail {
				t.Errorf("expected %d, got %d", tc.expectAvail, available)
			}
		})
	}
}
