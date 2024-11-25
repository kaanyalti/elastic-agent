//go:build integration

package integration

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/elastic/elastic-agent-libs/kibana"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools"
	"github.com/elastic/elastic-agent/pkg/testing/tools/check"
	"github.com/elastic/elastic-agent/pkg/testing/tools/fleettools"
	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/require"
)

func TestEnrollUnprivileged(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: Default,
		Stack: &define.Stack{},
		Sudo:  true,
	})
	t.Run("unenrolled unprivileged agent re-enrolls successfully using root user", func(t *testing.T) {
		ctx := context.Background()
		fixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
		require.NoError(t, err)
		installOpts := atesting.InstallOpts{
			NonInteractive: true,
			Force:          true,
			Privileged:     false,
		}

		randId := uuid.Must(uuid.NewV4()).String()
		policyReq := kibana.AgentPolicy{
			Name:        "test-policy-" + randId,
			Namespace:   "default",
			Description: "Test policy " + randId,
			MonitoringEnabled: []kibana.MonitoringEnabledOption{
				kibana.MonitoringEnabledLogs,
				kibana.MonitoringEnabledMetrics,
			},
		}
		fmt.Println("===================== CREATE POLICY =====================")
		policy, err := info.KibanaClient.CreatePolicy(ctx, policyReq)
		require.NoError(t, err)

		fmt.Println("===================== CREATE ENROLLMENT TOKEN =====================")
		enrollmentApiKey, err := tools.CreateEnrollmentToken(t, ctx, info.KibanaClient, policy.ID)
		require.NoError(t, err)

		fmt.Println("===================== INSTALL AGENT WITH TOKEN =====================")
		err = tools.InstallAgentForPolicyWithToken(ctx, t, installOpts, fixture, info.KibanaClient, policy.ID, enrollmentApiKey)
		require.NoError(t, err)

		hostname, err := os.Hostname()
		require.NoError(t, err)

		fmt.Printf("===================== INSTALL AGENT WITH TOKEN: %+v =====================", hostname)
		agent, err := fleettools.GetAgentByPolicyIDAndHostnameFromList(ctx, info.KibanaClient, policy.ID, hostname)
		require.NoError(t, err)

		fmt.Printf("====================== UNENROLL AGENT: %+v ====================\n", agent)
		ur, err := info.KibanaClient.UnEnrollAgent(ctx, kibana.UnEnrollAgentRequest{ID: agent.ID})
		require.NoError(t, err)

		fmt.Printf("================ UNENROLL RESPONSE: %+v =====================\n", ur)

		enrollUrl, err := fleettools.DefaultURL(ctx, info.KibanaClient)
		require.NoError(t, err)

		enrollArgs := []string{"elastic-agent", "enroll", "--url", enrollUrl, "--enrollment-token", enrollmentApiKey.APIKey, "--force"}

		// out, err := fixture.Exec(ctx, enrollArgs)
		// require.Error(t, err)
		//
		fmt.Println("======================= ENROLL CMD ====================")
		out, err := exec.CommandContext(ctx, "sudo", enrollArgs...).CombinedOutput()
		require.NoError(t, err)
		fmt.Printf("========= COMMAND OUTPUT %+v =========\n", string(out))

		// t.Logf(">>> Enroll succeeded. Output: %s", out)
		// timeout := 2 * time.Minute
		// if deadline, ok := ctx.Deadline(); ok {
		// 	timeout = time.Until(deadline)
		// }

		status, err := fleettools.GetAgentStatus(ctx, info.KibanaClient, policy.ID)

		fmt.Printf("================= AGENT STATUS: %+v =================\n", status)

		t.Logf(">>> Enroll succeeded. Output: %s", out)
		timeout := 2 * time.Minute
		if deadline, ok := ctx.Deadline(); ok {
			timeout = time.Until(deadline)
		}
		// Wait for Agent to be healthy
		require.Eventually(
			t,
			check.FleetAgentStatus(ctx, t, info.KibanaClient, policy.ID, "online"),
			timeout,
			10*time.Second,
			"Elastic Agent status is not online",
		)

		// require.True(t, false)
		// Wait for Agent to be healthy
		// require.Eventually(
		// 	t,
		// 	check.FleetAgentStatus(ctx, t, info.KibanaClient, policy.ID, "online"),
		// 	timeout,
		// 	10*time.Second,
		// 	"Elastic Agent status is not online",
		// )
	})
}
