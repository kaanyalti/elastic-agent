//go:build integration

package integration

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"testing"

	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/stretchr/testify/require"
)

func TestOtelConfigVerification(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: Default,
		Local: true,
		Sudo:  true,
	})
	//
	// t.Run("file-provider", func(t *testing.T) {
	// 	fixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
	// 	require.NoError(t, err)
	//
	// 	out, err := fixture.Exec(context.Background(), []string{"otel", "validate", "--config=./test-otel-config.yml"})
	// 	require.NoError(t, err, string(string(out)))
	// })
	//
	// t.Run("env-provider", func(t *testing.T) {
	// 	fixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
	// 	require.NoError(t, err)
	//
	// 	envVarName := "TEST_OTEL_CONFIG"
	// 	testConf, err := os.ReadFile("./test-otel-config.yml")
	// 	require.NoError(t, err)
	//
	// 	err = os.Setenv(envVarName, string(testConf))
	// 	require.NoError(t, err)
	// 	defer func() {
	// 		err := os.Unsetenv(envVarName)
	// 		require.NoError(t, err)
	// 	}()
	//
	// 	out, err := fixture.Exec(context.Background(), []string{"otel", "validate", fmt.Sprintf("--config=env:%s", envVarName)})
	// 	require.NoError(t, err, string(string(out)))
	// })
	//
	// t.Run("yaml-provider", func(t *testing.T) {
	// 	fixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
	// 	require.NoError(t, err)
	//
	// 	out, err := fixture.Exec(context.Background(), []string{"otel", "validate", "--config=./test-otel-config.yml", "--config=yaml:testing::test::t: 1"})
	// 	require.NoError(t, err, string(out))
	// })
	//
	// t.Run("http-provider", func(t *testing.T) {
	// 	fixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
	// 	require.NoError(t, err)
	//
	// 	testConf, err := os.ReadFile("./test-otel-config.yml")
	// 	require.NoError(t, err)
	//
	// 	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	// 		w.Write(testConf)
	// 	}))
	// 	defer server.Close()
	//
	// 	out, err := fixture.Exec(context.Background(), []string{"otel", "validate", fmt.Sprintf("--config=%s", server.URL)})
	// 	require.NoError(t, err, string(string(out)))
	// })
	t.Run("https-provider", func(t *testing.T) {
		// tempDir := t.TempDir()

		fixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
		require.NoError(t, err)

		testConf, err := os.ReadFile("./test-otel-config.yml")
		require.NoError(t, err)

		// Generate CA private key and self-signed certificate
		out, err := exec.Command("openssl", "genrsa", "-out", "myca.key", "2048").CombinedOutput()
		require.NoError(t, err, string(out))
		t.Log(string(out))

		// out, err = exec.Command("openssl", "req", "-x509", "-new", "-nodes", "-key", "myca.key", "-sha256", "-days", "365", "-out", "myca.crt", "-subj", "/CN=LocalTestCA", "-addext", "subjectAltName=DNS:localhost").CombinedOutput()
		out, err = exec.Command("openssl", "req", "-x509", "-new", "-nodes", "-key", "myca.key", "-sha256", "-days", "365", "-out", "myca.crt", "-subj", "/CN=LocalTestCA", "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=keyCertSign,cRLSign").CombinedOutput()
		require.NoError(t, err, string(out))
		t.Log(string(out))

		out, err = exec.Command("openssl", "genrsa", "-out", "server.key", "2048").CombinedOutput()
		require.NoError(t, err, string(out))
		t.Log(string(out))

		out, err = exec.Command("openssl", "req", "-new", "-key", "server.key", "-out", "server.csr", "-config", "san.conf").CombinedOutput()
		require.NoError(t, err, string(out))
		t.Log(string(out))

		out, err = exec.Command("openssl", "x509", "-req", "-in", "server.csr", "-CA", "myca.crt", "-CAkey", "myca.key", "-CAcreateserial", "-out", "server.crt", "-days", "365", "-sha256", "-extfile", "san.conf", "-extensions", "req_ext").CombinedOutput()
		require.NoError(t, err, string(out))
		t.Log(string(out))

		out, err = exec.Command("sudo", "cp", "myca.crt", "/usr/local/share/ca-certificates/").CombinedOutput()
		require.NoError(t, err, string(out))
		t.Log(string(out))

		out, err = exec.Command("sudo", "update-ca-certificates").CombinedOutput()
		require.NoError(t, err, string(out))
		t.Log(string(out))

		cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
		require.NoError(t, err)

		tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}

		server := &http.Server{
			Addr: ":3030",
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Write(testConf)
			}),
			TLSConfig: tlsConfig,
		}

		srvErrCh := make(chan error, 1)
		go func() {
			fmt.Println("=============")
			fmt.Println(server)
			fmt.Println("============")
			err := server.ListenAndServeTLS("", "")
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				srvErrCh <- err
			}
			close(srvErrCh)
		}()

		out, err = fixture.Exec(context.Background(), []string{"otel", "validate", "--config=https://localhost:3030"})
		require.NoError(t, err, string(string(out)))

		server.Close()
		// require.NoError(t, err, fmt.Sprintf("error closing server: %s", err.Error()))

		if srvErr := <-srvErrCh; srvErr != nil {
			require.NoError(t, srvErr, srvErr.Error())
		}
	})
}
