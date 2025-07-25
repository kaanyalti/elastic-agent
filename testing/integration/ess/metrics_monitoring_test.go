// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package ess

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/elastic/elastic-agent-libs/kibana"
	"github.com/elastic/elastic-agent-libs/testing/estools"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools"
	"github.com/elastic/elastic-agent/testing/integration"
)

type MetricsRunner struct {
	suite.Suite
	info         *define.Info
	agentFixture *atesting.Fixture

	ESHost string
}

func TestMetricsMonitoringCorrectBinaries(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: integration.Fleet,
		Stack: &define.Stack{},
		Local: false, // requires Agent installation
		Sudo:  true,  // requires Agent installation
		OS: []define.OS{
			{Type: define.Linux},
			{Type: define.Windows},
		},
	})

	suite.Run(t, &MetricsRunner{info: info})
}

func (runner *MetricsRunner) SetupSuite() {
	fixture, err := define.NewFixtureFromLocalBuild(runner.T(), define.Version())
	require.NoError(runner.T(), err)
	runner.agentFixture = fixture

	policyUUID := uuid.Must(uuid.NewV4()).String()
	basePolicy := kibana.AgentPolicy{
		Name:        "test-policy-" + policyUUID,
		Namespace:   "default",
		Description: "Test policy " + policyUUID,
		MonitoringEnabled: []kibana.MonitoringEnabledOption{
			kibana.MonitoringEnabledLogs,
			kibana.MonitoringEnabledMetrics,
		},
	}

	installOpts := atesting.InstallOpts{
		NonInteractive: true,
		Force:          true,
		Privileged:     true,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	policyResp, _, err := tools.InstallAgentWithPolicy(ctx, runner.T(), installOpts, runner.agentFixture, runner.info.KibanaClient, basePolicy)
	require.NoError(runner.T(), err)

	_, err = tools.InstallPackageFromDefaultFile(ctx, runner.info.KibanaClient, "system",
		integration.PreinstalledPackages["system"], "testdata/system_integration_setup.json", uuid.Must(uuid.NewV4()).String(), policyResp.ID)
	require.NoError(runner.T(), err)

}

func (runner *MetricsRunner) TestBeatsMetrics() {
	t := runner.T()

	UnitOutputName := "default"
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute*20)
	defer cancel()

	agentStatus, err := runner.agentFixture.ExecStatus(ctx)
	require.NoError(t, err, "could not to get agent status")

	componentIds := []string{
		fmt.Sprintf("system/metrics-%s", UnitOutputName),
		fmt.Sprintf("log-%s", UnitOutputName),
		"beat/metrics-monitoring",
		"elastic-agent",
		"http/metrics-monitoring",
		"filestream-monitoring",
	}

	now := time.Now()
	var query map[string]any
	defer func() {
		if t.Failed() {
			bs, err := json.Marshal(query)
			if err != nil {
				// nothing we can do, just log the map
				t.Errorf("executed at %s: %v",
					now.Format(time.RFC3339Nano), query)
				return
			}
			t.Errorf("executed at %s: query: %s",
				now.Format(time.RFC3339Nano), string(bs))
		}
	}()

	t.Logf("starting to ES for metrics at %s", now.Format(time.RFC3339Nano))
	require.Eventually(t, func() bool {
		for _, cid := range componentIds {
			query = genESQuery(agentStatus.Info.ID,
				[][]string{
					{"match", "component.id", cid},
					{"exists", "field", "system.process.cpu.total.value"},
					{"exists", "field", "system.process.memory.size"},
				})
			now = time.Now()
			res, err := estools.PerformQueryForRawQuery(ctx, query, "metrics-elastic_agent*", runner.info.ESClient)
			require.NoError(t, err)
			t.Logf("Fetched metrics for %s, got %d hits", cid, res.Hits.Total.Value)
			if res.Hits.Total.Value < 1 {
				return false
			}
		}
		return true
	}, time.Minute*10, time.Second*10, "could not fetch metrics for all known components in default install: %v", componentIds)
}

func genESQuery(agentID string, requiredFields [][]string) map[string]interface{} {
	fieldsQ := make([]map[string]interface{}, 0, 2+len(requiredFields))
	fieldsQ = append(fieldsQ, map[string]interface{}{
		"match": map[string]interface{}{
			"agent.id": agentID,
		},
	})
	for _, f := range requiredFields {
		if len(f) != 3 {
			continue
		}
		fieldsQ = append(fieldsQ,
			map[string]interface{}{
				f[0]: map[string]interface{}{
					f[1]: f[2],
				},
			})
	}

	// see https://github.com/elastic/kibana/blob/main/x-pack/plugins/fleet/server/services/agents/agent_metrics.ts
	queryRaw := map[string]interface{}{
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"must": fieldsQ,
			},
		},
	}

	return queryRaw
}
