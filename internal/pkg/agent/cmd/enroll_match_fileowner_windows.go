//go:build windows

package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"unsafe"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"golang.org/x/sys/windows"
)

// Constants for LogonUser
const (
	LOGON32_LOGON_NETWORK     uint32 = 3
	LOGON32_LOGON_INTERACTIVE        = 2
	LOGON32_LOGON_BATCH              = 4
	LOGON32_PROVIDER_DEFAULT         = 0
)

var (
	advapi32       = windows.NewLazySystemDLL("advapi32.dll")
	procLogonUserW = advapi32.NewProc("LogonUserW")
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

	fmt.Printf("=============== WINDOWS OWNER: %+v ===============\n", owner)
	return owner.String(), nil
}

func readPassword(path string) (string, error) {
	password, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("error while reading windows user password: %w", err)
	}

	return string(password), nil
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

	// Get the token use
	tokenUser, err := token.GetTokenUser()
	if err != nil {
		return "", fmt.Errorf("failed to get token user: %w", err)
	}

	fmt.Printf("=============== CURRENT USER TOKEN: %+v =================\n", tokenUser)
	return tokenUser.User.Sid.String(), nil
}

func isFileOwner(curUser string, fileOwner string) (bool, error) {
	var cSid *windows.SID
	err := windows.ConvertStringSidToSid(windows.StringToUTF16Ptr(curUser), &cSid)
	if err != nil {
		return false, fmt.Errorf("failed to convert SID string to SID: %w", err)
	}

	var fSid *windows.SID
	err = windows.ConvertStringSidToSid(windows.StringToUTF16Ptr(fileOwner), &fSid)
	if err != nil {
		return false, fmt.Errorf("failed to convert SID string to SID: %w", err)
	}

	isEqual := fSid.Equals(cSid)
	fmt.Printf("============================\nIS FILE OWNER: %+v\nIS FILE OWNER SECOND SID %+v\n IS EQUAL: %v\n =============================\n", cSid, fSid, isEqual)

	return isEqual, nil
}

func windowsLogonUser(username string, domain string, password string, logonType uint32, logonProvider uint32) (windows.Token, error) {
	var token windows.Token

	fmt.Println("================ USER NAME POINTER ================")
	usernamePtr, err := windows.UTF16PtrFromString(username)
	if err != nil {
		return 0, err
	}
	fmt.Println("================ DOMAIN POINTER ================")
	domainPtr, err := windows.UTF16PtrFromString(domain)
	if err != nil {
		return 0, err
	}

	fmt.Println("================ PASSWORD POINTER ================")
	passwordPtr, err := windows.UTF16PtrFromString(password)
	if err != nil {
		return 0, err
	}

	ret, _, err := procLogonUserW.Call(
		uintptr(unsafe.Pointer(usernamePtr)),
		uintptr(unsafe.Pointer(domainPtr)),
		uintptr(unsafe.Pointer(passwordPtr)),
		uintptr(logonType),
		uintptr(logonProvider),
		uintptr(unsafe.Pointer(&token)),
	)

	fmt.Printf("=============== CALL RETURN: %v ==============\n", ret)
	if ret == 0 {
		return 0, err
	}
	fmt.Printf("====================== TOKEN %+v ===================\n", token)
	return token, nil
}

func execWithFileOwnerFunc(fileOwner string, filePath string) (func() error, error) {
	var sid *windows.SID
	err := windows.ConvertStringSidToSid(windows.StringToUTF16Ptr(fileOwner), &sid)
	if err != nil {
		return nil, fmt.Errorf("failed to convert SID string to SID: %w", err)
	}

	var accountName [256]uint16 // buffer to hold the account name
	var domainName [256]uint16  // buffer to hold the domain name
	var accountNameLen uint32 = 256
	var domainNameLen uint32 = 256
	var accountType uint32

	fmt.Printf("================== GOING TO LOOKUP ACCOUNT BY SID: %+v =======================\n", sid)
	err = windows.LookupAccountSid(
		nil,
		sid,
		&accountName[0], // need the pointer to the start of the buffer
		&accountNameLen,
		&domainName[0], // need the pointer to the start of the buffer
		&domainNameLen,
		&accountType,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup account using SID: %w", err)
	}

	username := windows.UTF16ToString(accountName[:accountNameLen]) // take what's relevant from the buffer
	domain := windows.UTF16ToString(domainName[:domainNameLen])

	fmt.Printf("======================== RESOLVED SID BELONGS TO: %s\\%s ==============================\n", domain, username)

	binPath := paths.Top()

	pwd, err := readPassword(filepath.Join(binPath, "windows-password"))
	if err != nil {
		return nil, fmt.Errorf("error while reading password: %w", err)
	}

	fmt.Printf("========================== READ PASSWORD: %s =====================\n", pwd)

	fmt.Println("============================= GOING TO LOGON AS USER =============================")
	token, err := windowsLogonUser(username, domain, pwd, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT)
	if err != nil {
		return nil, fmt.Errorf("error logging in as user: %w", err)
	}

	fmt.Println("============================= BUILDING COMMAND ==============================")
	enrollCmd := exec.Command(binPath, os.Args[1:]...)

	enrollCmd.SysProcAttr = &syscall.SysProcAttr{
		Token: syscall.Token(token),
	}

	enrollCmd.Stdin = os.Stdin
	enrollCmd.Stdout = os.Stdout
	enrollCmd.Stderr = os.Stderr

	return func() error { return errors.New("test error") }, nil
}

// get file owner
// check if file owner is root
// if not build command
// execute command
//
