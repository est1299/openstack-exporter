package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/openstack-exporter/openstack-exporter/exporters"
	"github.com/openstack-exporter/openstack-exporter/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSetAutoServicesState(t *testing.T) {
	serviceStates := map[string]serviceState{
		"compute": serviceEnabled,
		"network": serviceAuto,
		"image":   serviceAuto,
	}

	setAutoServicesState(serviceStates, serviceDisabled)
	assert.Equal(t, serviceEnabled, serviceStates["compute"])
	assert.Equal(t, serviceDisabled, serviceStates["network"])
	assert.Equal(t, serviceDisabled, serviceStates["image"])
}

func TestApplyAutodetection(t *testing.T) {
	serviceStates := map[string]serviceState{
		"compute": serviceEnabled,
		"network": serviceAuto,
		"image":   serviceAuto,
		"dns":     serviceDisabled,
	}

	applyAutodetection(serviceStates, []string{"network"})
	assert.Equal(t, serviceEnabled, serviceStates["compute"])
	assert.Equal(t, serviceEnabled, serviceStates["network"])
	assert.Equal(t, serviceDisabled, serviceStates["image"])
	assert.Equal(t, serviceDisabled, serviceStates["dns"])
}

func TestGetEnabledServicesFromStates(t *testing.T) {
	serviceStates := make(map[string]serviceState, len(exporters.SupportedExporters))
	for _, service := range exporters.SupportedExporters {
		serviceStates[service] = serviceDisabled
	}
	serviceStates["compute"] = serviceEnabled
	serviceStates["network"] = serviceEnabled

	services := getEnabledServicesFromStates(serviceStates)
	assert.ElementsMatch(t, []string{"compute", "network"}, services)
}

const keystoneTokenResponse = `{"token": {"catalog": [
	{"type": "compute", "endpoints": [{"interface": "public", "region": "RegionOne", "url": "https://nova.test/v2.1"}]},
	{"type": "identity", "endpoints": [{"interface": "public", "region": "RegionOne", "url": "https://keystone.test/v3"}]},
	{"type": "network", "endpoints": [{"interface": "public", "region": "RegionOne", "url": "https://neutron.test"}]}
]}}`

// newTLSKeystone starts a fake Keystone over HTTPS that only answers token requests, using tlsConfig if set.
func newTLSKeystone(t *testing.T, tlsConfig *tls.Config) *httptest.Server {
	t.Helper()

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v3/auth/tokens" {
			t.Errorf("unexpected request to fake Keystone: %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Subject-Token", "1234")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(keystoneTokenResponse))
	}))
	srv.TLS = tlsConfig
	srv.Config.ErrorLog = log.New(io.Discard, "", 0) // silence expected TLS handshake failures
	srv.StartTLS()
	t.Cleanup(srv.Close)

	return srv
}

// testPKI is a CA that issued a server certificate for 127.0.0.1 and a client certificate.
type testPKI struct {
	caPEM         []byte
	caPool        *x509.CertPool
	server        tls.Certificate
	clientCertPEM []byte
	clientKeyPEM  []byte
}

func newTestPKI(t *testing.T) testPKI {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)

	issue := func(serial int64, usage x509.ExtKeyUsage) (certPEM, keyPEM []byte) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		template := &x509.Certificate{
			SerialNumber: big.NewInt(serial),
			Subject:      pkix.Name{CommonName: "127.0.0.1"},
			IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
			NotBefore:    caTemplate.NotBefore,
			NotAfter:     caTemplate.NotAfter,
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{usage},
		}
		der, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
		require.NoError(t, err)
		keyDER, err := x509.MarshalPKCS8PrivateKey(key)
		require.NoError(t, err)
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
			pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	}

	serverCertPEM, serverKeyPEM := issue(2, x509.ExtKeyUsageServerAuth)
	server, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	require.NoError(t, err)
	clientCertPEM, clientKeyPEM := issue(3, x509.ExtKeyUsageClientAuth)

	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)

	return testPKI{
		caPEM:         pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		caPool:        caPool,
		server:        server,
		clientCertPEM: clientCertPEM,
		clientKeyPEM:  clientKeyPEM,
	}
}

// mutualTLSConfig makes the fake Keystone require a client certificate issued by the CA.
func (p testPKI) mutualTLSConfig() *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{p.server},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    p.caPool,
	}
}

func writeTempFile(t *testing.T, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	require.NoError(t, os.WriteFile(path, data, 0o600))
	return path
}

func serverCAFile(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	return writeTempFile(t, "ca.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}))
}

// writeCloudsYAML points OS_CLIENT_CONFIG_FILE at a clouds.yaml for "tls.cloud", with extra appended to its entry.
func writeCloudsYAML(t *testing.T, authURL, extra string) {
	t.Helper()

	config := fmt.Sprintf(`clouds:
  tls.cloud:
    region_name: RegionOne
    identity_api_version: 3
    auth:
      username: 'admin'
      password: 'admin'
      project_name: 'admin'
      project_domain_name: 'Default'
      user_domain_name: 'Default'
      auth_url: '%s/v3'
%s`, authURL, extra)

	path := filepath.Join(t.TempDir(), "clouds.yaml")
	require.NoError(t, os.WriteFile(path, []byte(config), 0o600))
	t.Setenv("OS_CLIENT_CONFIG_FILE", path)
}

func TestAutodetectServicesTLS(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	t.Run("honors cacert from clouds.yaml", func(t *testing.T) {
		srv := newTLSKeystone(t, nil)
		writeCloudsYAML(t, srv.URL, fmt.Sprintf("    cacert: '%s'\n", serverCAFile(t, srv)))

		services, err := autodetectServices("tls.cloud", logger)
		require.NoError(t, err)
		assert.Subset(t, services, []string{"compute", "identity", "network"})
	})

	// Control: proves the case above passes because of cacert.
	t.Run("rejects untrusted certificate without cacert", func(t *testing.T) {
		srv := newTLSKeystone(t, nil)
		writeCloudsYAML(t, srv.URL, "")

		_, err := autodetectServices("tls.cloud", logger)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "x509")
	})

	t.Run("honors client certificate from clouds.yaml", func(t *testing.T) {
		pki := newTestPKI(t)
		srv := newTLSKeystone(t, pki.mutualTLSConfig())
		writeCloudsYAML(t, srv.URL, fmt.Sprintf("    cacert: '%s'\n    cert: '%s'\n    key: '%s'\n",
			writeTempFile(t, "ca.pem", pki.caPEM),
			writeTempFile(t, "client.crt", pki.clientCertPEM),
			writeTempFile(t, "client.key", pki.clientKeyPEM)))

		services, err := autodetectServices("tls.cloud", logger)
		require.NoError(t, err)
		assert.Subset(t, services, []string{"compute", "identity", "network"})
	})

	// Control: proves the case above passes because of cert and key.
	t.Run("rejects missing client certificate", func(t *testing.T) {
		pki := newTestPKI(t)
		srv := newTLSKeystone(t, pki.mutualTLSConfig())
		writeCloudsYAML(t, srv.URL, fmt.Sprintf("    cacert: '%s'\n", writeTempFile(t, "ca.pem", pki.caPEM)))

		_, err := autodetectServices("tls.cloud", logger)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "certificate required")
	})
}

func TestNewExporterTLS(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	newExporter := func() error {
		_, err := exporters.NewExporter("identity", "openstack", "tls.cloud", nil, "public", false, false, false, false,
			"", "", new(utils.LabelMappingFlag), 1, nil, logger)
		return err
	}

	t.Run("honors cacert from clouds.yaml", func(t *testing.T) {
		srv := newTLSKeystone(t, nil)
		writeCloudsYAML(t, srv.URL, fmt.Sprintf("    cacert: '%s'\n", serverCAFile(t, srv)))

		require.NoError(t, newExporter())
	})

	// Control: proves the case above passes because of cacert.
	t.Run("rejects untrusted certificate without cacert", func(t *testing.T) {
		srv := newTLSKeystone(t, nil)
		writeCloudsYAML(t, srv.URL, "")

		err := newExporter()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "x509")
	})
}

// resolveServiceConfig is the startup path main runs; an error here makes the exporter exit.
func TestResolveServiceConfigTLS(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	params := func() ResolveServiceConfigParams {
		serviceStates := make(map[string]serviceState, len(exporters.SupportedExporters))
		for _, service := range exporters.SupportedExporters {
			serviceStates[service] = serviceAuto
		}
		serviceStates["network"] = serviceDisabled
		return ResolveServiceConfigParams{Cloud: "tls.cloud", ServiceStates: serviceStates}
	}

	t.Run("enables autodetected services with cacert from clouds.yaml", func(t *testing.T) {
		srv := newTLSKeystone(t, nil)
		writeCloudsYAML(t, srv.URL, fmt.Sprintf("    cacert: '%s'\n", serverCAFile(t, srv)))

		services, err := resolveServiceConfig(params(), logger)
		require.NoError(t, err)
		assert.ElementsMatch(t, []string{"compute", "identity"}, services)
	})

	// Control: proves the case above passes because of cacert.
	t.Run("fails startup without cacert", func(t *testing.T) {
		srv := newTLSKeystone(t, nil)
		writeCloudsYAML(t, srv.URL, "")

		services, err := resolveServiceConfig(params(), logger)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "x509")
		assert.Nil(t, services)
	})
}

func TestSelectServicesForRequest(t *testing.T) {
	configured := []string{"compute", "network", "image"}
	tests := []struct {
		name      string
		url       string
		expected  []string
		errSubstr string
	}{
		{
			name:     "filters with include and exclude",
			url:      "/probe?include_services=compute,image&exclude_services=image",
			expected: []string{"compute"},
		},
		{
			name:     "normalizes spaces and duplicates",
			url:      "/probe?include_services=compute,%20compute%20,network",
			expected: []string{"compute", "network"},
		},
		{
			name:      "rejects invalid include service",
			url:       "/probe?include_services=compute,bad",
			errSubstr: "invalid include_services",
		},
		{
			name:      "rejects invalid exclude service",
			url:       "/probe?exclude_services=bad",
			errSubstr: "invalid exclude_services",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", tc.url, nil)
			services, err := selectServicesForRequest(configured, req)

			if tc.errSubstr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.errSubstr)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.expected, services)
		})
	}
}
