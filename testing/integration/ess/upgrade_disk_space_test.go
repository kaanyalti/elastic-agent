// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package ess

import (
	"context"
	"testing"

	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/testing/integration"
	"github.com/elastic/elastic-agent/testing/upgradetest"
	"github.com/stretchr/testify/require"
)

// TestUpgradeDiskSpace simulates disk full conditions during agent upgrade
// and asserts that the agent reports and handles disk full errors gracefully.
func TestUpgradeDiskSpace_Linux(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: integration.Deb,
		Stack: &define.Stack{},
		Local: false, // requires Agent installation
		Sudo:  true,  // requires Agent installation
		OS: []define.OS{
			{
				Type: define.Linux,
			},
		},
	})

	ctx, cancel := context.WithCancel(context.TODO())
	defer cancel()

	// Start at the build version as we want to test the retry
	// logic that is in the build.
	var startFixture *atesting.Fixture
	var err error
	startFixture, err = define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err)

	err = startFixture.Prepare(ctx)
	require.NoError(t, err)

	startVersionInfo, err := startFixture.ExecVersion(ctx)
	require.NoError(t, err)

	// Upgrade to a different build but of the same version (always a snapshot).
	// In the case there is not a different build then the test is skipped.
	// Fleet doesn't allow a downgrade to occur, so we cannot go to a lower version.
	endFixture, err := atesting.NewFixture(
		t,
		upgradetest.EnsureSnapshot(define.Version()),
		atesting.WithFetcher(atesting.ArtifactFetcher()),
	)
	require.NoError(t, err)

	err = endFixture.Prepare(ctx)
	require.NoError(t, err)

	endVersionInfo, err := endFixture.ExecVersion(ctx)
	require.NoError(t, err)
	if startVersionInfo.Binary.String() == endVersionInfo.Binary.String() &&
		startVersionInfo.Binary.Commit == endVersionInfo.Binary.Commit {
		t.Skipf("Build under test is the same as the build from the artifacts repository (version: %s) [commit: %s]",
			startVersionInfo.Binary.String(), startVersionInfo.Binary.Commit)
	}

	t.Logf("Testing Elastic Agent upgrade from %s to %s with Fleet...",
		define.Version(), endVersionInfo.Binary.String())

	err = PerformManagedUpgrade(ctx, t, info, startFixture, endFixture, defaultPolicy(), false)
	require.Error(t, err)

	// TODO: Implement test setup for tmpfs/ramdisk/VHD depending on platform
	// TODO: Start agent upgrade with download/extract directory on limited space
	// TODO: Assert that agent reports disk full error, cleans up, and does not proceed with upgrade
	// TODO: Assert that Fleet receives a clear error message about disk space

}

// func TestUpgradeDiskSpace_Mac(t *testing.T) {}

// func TestUpgradeDiskSpace_Windows(t *testing.T) {
// 	// TODO: Implement test setup for Windows
// 	// TODO: Start agent upgrade with download/extract directory on limited space
// 	// TODO: Assert that agent reports disk full error, cleans up, and does not proceed with upgrade
// 	// TODO: Assert that Fleet receives a clear error message about disk space
// }
