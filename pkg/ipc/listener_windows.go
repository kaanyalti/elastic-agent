// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build windows

package ipc

import (
	"fmt"
	"net"
	"os/user"
	"strings"

	"golang.org/x/sys/windows"

	"github.com/elastic/elastic-agent-libs/api/npipe"

	"github.com/elastic/elastic-agent/internal/pkg/acl"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/pkg/core/constants"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/utils"
)

const schemeNpipePrefix = "npipe://"

func IsLocal(address string) bool {
	return strings.HasPrefix(address, schemeNpipePrefix)
}

// CreateListener creates net listener from address string
// Shared for control and beats comms sockets
func CreateListener(log *logger.Logger, address string) (net.Listener, error) {
	sd, err := securityDescriptor(log)
	if err != nil {
		return nil, fmt.Errorf("failed to create security descriptor: %w", err)
	}
	lis, err := npipe.NewListener(npipe.TransformString(address), sd)
	if err != nil {
		return nil, fmt.Errorf("failed to create npipe listener: %w", err)
	}
	return lis, nil
}

func CleanupListener(log *logger.Logger, address string) {
	// nothing to do on windows
}

func securityDescriptor(log *logger.Logger) (string, error) {
	u, err := user.Current()
	if err != nil {
		return "", fmt.Errorf("failed to get current user: %w", err)
	}

	descriptor := "D:P(A;;GA;;;" + u.Uid + ")"

	isAdmin, err := utils.HasRoot()
	if err != nil {
		// do not fail, agent would end up in a loop, continue with limited permissions
		log.Warnf("failed to detect Administrator: %w", err)
		isAdmin = false // just in-case to ensure that in error case that its always false
	}
	// SYSTEM/Administrators can always talk over the pipe
	descriptor += "(A;;GA;;;" + utils.AdministratorSID + ")"

	// Only add elastic-agent group permissions if:
	// 1. Running as admin (command is started by admin)
	// 2. Agent is installed (RunningInstalled is true)
	// 3. Agent is running as elastic-agent user
	if isAdmin && paths.RunningInstalled() {
		// Check if the agent is running as elastic-agent user
		agentUser, err := user.Lookup(constants.ElasticUsername)
		if err != nil {
			return "", fmt.Errorf("failed to lookup elastic-agent user: %w", err)
		}

		if agentUser.Uid == u.Uid {
			// Add elastic-agent group permissions only if running as elastic-agent-user
			gid, err := pathGID(paths.Top())
			if err != nil {
				return "", fmt.Errorf("failed to detect group: %w", err)
			}
			descriptor += "(A;;GA;;;" + gid + ")"
		}
	}

	return descriptor, nil
}

func pathGID(path string) (string, error) {
	var group *windows.SID
	var secDesc windows.Handle
	err := acl.GetNamedSecurityInfo(
		path,
		acl.SE_FILE_OBJECT,
		acl.GROUP_SECURITY_INFORMATION,
		nil,
		&group,
		nil,
		nil,
		&secDesc,
	)
	if err != nil {
		return "", fmt.Errorf("call to GetNamedSecurityInfo at %s failed: %w", path, err)
	}
	defer func() {
		_, _ = windows.LocalFree(secDesc)
	}()
	if group == nil {
		return "", fmt.Errorf("failed to determine group using GetNamedSecurityInfo at %s", path)
	}
	return group.String(), nil
}
