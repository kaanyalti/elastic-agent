//go:build !windows

package download

import (
	"errors"
	"syscall"
	"testing"

	"github.com/elastic/elastic-agent/pkg/core/logger"
)

func statfsProvider(bfree, bavail, bsize int64, retErr error) func(string, *syscall.Statfs_t) error {
	return func(_ string, stat *syscall.Statfs_t) error {
		stat.Bfree = uint64(bfree)
		stat.Bavail = uint64(bavail)
		stat.Bsize = uint32(bsize)
		return retErr
	}
}

func hasRootProvider(isRoot bool, retErr error) func() (bool, error) {
	return func() (bool, error) {
		return isRoot, retErr
	}
}

type diskProps struct {
	bfree     int64
	bavail    int64
	bsize     int64
	statfsErr error
}

type permProps struct {
	isRoot     bool
	hasRootErr error
}

type testCase struct {
	disk        diskProps
	perm        permProps
	expectAvail uint64
	expectErr   bool
}

func TestCheckDiskSpaceUnix(t *testing.T) {
	tests := map[string]testCase{
		"root user, no errors": {
			disk:        diskProps{100, 80, 4096, nil},
			perm:        permProps{true, nil},
			expectAvail: 100 * 4096,
			expectErr:   false,
		},
		"non-root user, no errors": {
			disk:        diskProps{100, 80, 4096, nil},
			perm:        permProps{false, nil},
			expectAvail: 80 * 4096,
			expectErr:   false,
		},
		"statfs error": {
			disk:        diskProps{0, 0, 0, errors.New("mock error")},
			perm:        permProps{true, nil},
			expectAvail: 0,
			expectErr:   true,
		},
		"hasRoot error": {
			disk:        diskProps{100, 80, 4096, nil},
			perm:        permProps{false, errors.New("mock error")},
			expectAvail: 0,
			expectErr:   true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			// Use a dummy logger for testing
			var testLogger *logger.Logger = nil
			available, err := checkDiskSpaceUnix(
				testLogger,
				"/mockPath",
				statfsProvider(tc.disk.bfree, tc.disk.bavail, tc.disk.bsize, tc.disk.statfsErr),
				hasRootProvider(tc.perm.isRoot, tc.perm.hasRootErr),
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
