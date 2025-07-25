// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package ess

import (
	"context"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/schollz/progressbar/v3"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/agent/install"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools/testcontext"
	"github.com/elastic/elastic-agent/testing/installtest"
	"github.com/elastic/elastic-agent/testing/integration"
)

func TestSwitchUnprivilegedWithoutBasePath(t *testing.T) {

	define.Require(t, define.Requirements{
		Group: integration.Default,
		// We require sudo for this test to run
		// `elastic-agent install`.
		Sudo: true,

		// It's not safe to run this test locally as it
		// installs Elastic Agent.
		Local: false,
		OS: []define.OS{
			{
				Type: define.Darwin,
			}, {
				Type: define.Linux,
			},
		},
	})

	// Get path to Elastic Agent executable
	fixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err)

	ctx, cancel := testcontext.WithDeadline(t, context.Background(), time.Now().Add(10*time.Minute))
	defer cancel()

	// Prepare the Elastic Agent so the binary is extracted and ready to use.
	err = fixture.Prepare(ctx)
	require.NoError(t, err)
	testSwitchUnprivilegedWithoutBasePathCustomUser(ctx, t, fixture, "", "")
}

func TestSwitchUnprivilegedWithoutBasePathCustomUser(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: integration.Default,
		// We require sudo for this test to run
		// `elastic-agent install`.
		Sudo: true,

		// It's not safe to run this test locally as it
		// installs Elastic Agent.
		Local: false,
		OS: []define.OS{
			{
				Type: define.Darwin,
			}, {
				Type: define.Linux,
			},
		},
	})

	// Get path to Elastic Agent executable
	fixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err)

	ctx, cancel := testcontext.WithDeadline(t, context.Background(), time.Now().Add(10*time.Minute))
	defer cancel()

	// Prepare the Elastic Agent so the binary is extracted and ready to use.
	err = fixture.Prepare(ctx)
	require.NoError(t, err)
	testSwitchUnprivilegedWithoutBasePathCustomUser(ctx, t, fixture, "tester", "testing")
}

func testSwitchUnprivilegedWithoutBasePathCustomUser(ctx context.Context, t *testing.T, fixture *atesting.Fixture, customUsername, customGroup string) {
	// Run `elastic-agent install`.  We use `--force` to prevent interactive
	// execution.
	opts := &atesting.InstallOpts{Force: true, Privileged: true}
	out, err := fixture.Install(ctx, opts)
	if err != nil {
		t.Logf("install output: %s", out)
		require.NoError(t, err)
	}

	// setup user
	if customUsername != "" {
		pt := progressbar.NewOptions(-1)
		_, err = install.EnsureUserAndGroup(customUsername, customGroup, pt, true)
		require.NoError(t, err)
	}

	// Check that Agent was installed in default base path in privileged mode
	require.NoError(t, installtest.CheckSuccess(ctx, fixture, opts.BasePath, &installtest.CheckOpts{Privileged: true}))

	// Switch to unprivileged mode
	args := []string{"unprivileged", "-f"}
	if customUsername != "" {
		args = append(args, "--user", customUsername)
	}

	if customGroup != "" {
		args = append(args, "--group", customGroup)
	}

	out, err = fixture.Exec(ctx, args)
	if err != nil {
		t.Logf("unprivileged output: %s", out)
		require.NoError(t, err)
	}

	// Check that Agent is running in default base path in unprivileged mode
	checks := &installtest.CheckOpts{
		Privileged: false,
		Username:   customUsername,
		Group:      customGroup,
	}
	require.NoError(t, installtest.CheckSuccess(ctx, fixture, opts.BasePath, checks))
}

func TestSwitchUnprivilegedWithBasePath(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: integration.Default,
		// We require sudo for this test to run
		// `elastic-agent install`.
		Sudo: true,

		// It's not safe to run this test locally as it
		// installs Elastic Agent.
		Local: false,
	})

	// Get path to Elastic Agent executable
	fixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err)

	ctx, cancel := testcontext.WithDeadline(t, context.Background(), time.Now().Add(10*time.Minute))
	defer cancel()

	// Prepare the Elastic Agent so the binary is extracted and ready to use.
	err = fixture.Prepare(ctx)
	require.NoError(t, err)

	// When running in unprivileged using a base path the
	// base needs to be accessible by the `elastic-agent-user` user that will be
	// executing the process, but is not created yet. Using a base that exists
	// and is known to be accessible by standard users, ensures this tests
	// works correctly and will not hit a permission issue when spawning the
	// elastic-agent service.
	var basePath string
	switch runtime.GOOS {
	case define.Linux:
		basePath = `/usr`
	case define.Windows:
		basePath = `C:\`
	default:
		// Set up random temporary directory to serve as base path for Elastic Agent
		// installation.
		tmpDir := t.TempDir()
		basePath = filepath.Join(tmpDir, strings.ToLower(randStr(8)))
	}

	// Run `elastic-agent install`.  We use `--force` to prevent interactive
	// execution.
	opts := &atesting.InstallOpts{
		BasePath:   basePath,
		Force:      true,
		Privileged: true,
	}
	out, err := fixture.Install(ctx, opts)
	if err != nil {
		t.Logf("install output: %s", out)
		require.NoError(t, err)
	}

	// Check that Agent was installed in the custom base path in privileged mode
	topPath := filepath.Join(basePath, "Elastic", "Agent")
	require.NoError(t, installtest.CheckSuccess(ctx, fixture, topPath, &installtest.CheckOpts{Privileged: true}))

	// Switch to unprivileged mode
	out, err = fixture.Exec(ctx, []string{"unprivileged", "-f"})
	if err != nil {
		t.Logf("unprivileged output: %s", out)
		require.NoError(t, err)
	}

	// Check that Agent is running in the custom base path in unprivileged mode
	require.NoError(t, installtest.CheckSuccess(ctx, fixture, topPath, &installtest.CheckOpts{Privileged: false}))
}
