//go:build windows

package cmd

import (
	"fmt"
	"os/exec"

	"golang.org/x/sys/windows"
)

func getFileOwner(filePath string) (string, error) {
	// Get security information of the file
	sd, err := windows.GetNamedSecurityInfo(
		filePath,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION,
	)
	if err != nil {
		return "", fmt.Errorf("failed to get security info: %w", err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return "", fmt.Errorf("failed to get security descriptor owner: %w", err)
	}
	return owner.String(), nil
}

// Helper to get the current user's SID
func getCurrentUser() (string, error) {
	// Get the token for the current process
	var token windows.Token
	err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token)
	if err != nil {
		return "", fmt.Errorf("failed to open process token: %w", err)
	}
	defer token.Close()

	// Get the token user
	tokenUser, err := token.GetTokenUser()
	if err != nil {
		return "", fmt.Errorf("failed to get token user: %w", err)
	}

	return tokenUser.User.Sid.String(), nil
}

func isFileOwner(curUser string, fileOwner string) (bool, error) {
	var cSid *windows.SID
	err := windows.ConvertStringSidToSid(windows.StringToUTF16Ptr(curUser), &cSid)
	if err != nil {
		return false, fmt.Errorf("failed to convert SID string to SID: %w", err)
	}

	var fSid *windows.SID
	err = windows.ConvertStringSidToSid(windows.StringToUTF16Ptr(curUser), &fSid)
	if err != nil {
		return false, fmt.Errorf("failed to convert SID string to SID: %w", err)
	}

	return fSid.Equals(cSid), nil
}

func execWithFileOwnerFunc(fileOwner string, filePath string) (func() error, error) {
	cmd := exec.Command("echo", "hello")
	return cmd.Run, nil
}

// get file owner
// check if file owner is root
// if not build command
// execute command
//
