package exporters

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"testing"

	"log/slog"

	clientutilsv2 "github.com/gophercloud/utils/v2/client"
	clientconfigv2 "github.com/gophercloud/utils/v2/openstack/clientconfig"
	"github.com/jarcoal/httpmock"
	"github.com/openstack-exporter/openstack-exporter/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

const baseFixturePath = "./fixtures"
const cloudName = "test.cloud"

type BaseOpenStackTestSuite struct {
	suite.Suite
	ServiceName string
	Prefix      string
	Exporter    *OpenStackExporter
}

func (suite *BaseOpenStackTestSuite) SetResponseFromFixture(method string, statusCode int, url string, file string) {
	data, _ := os.ReadFile(file)
	response := &http.Response{
		Body: httpmock.NewRespBodyFromBytes(data),
		Header: http.Header{
			"Content-Type":    []string{"application/json"},
			"X-Subject-Token": []string{"1234"},
		},
		StatusCode: statusCode,
	}

	responder := httpmock.ResponderFromResponse(response).Times(2)
	httpmock.RegisterResponder(method, url, responder)
}

func (suite *BaseOpenStackTestSuite) MakeURL(resource string, port string) string {
	if port != "" {
		return fmt.Sprintf("http://%s:%s%s", cloudName, port, resource)
	}
	return fmt.Sprintf("http://%s%s", cloudName, resource)
}

func (suite *BaseOpenStackTestSuite) FixturePath(name string) string {
	return fmt.Sprintf("%s/%s", baseFixturePath, name+".json")
}

var fixtures map[string]string = map[string]string{
	"/container-infra/":              "container_infra_api_discovery",
	"/container-infra/clusters":      "container_infra_clusters",
	"/compute/":                      "nova_api_discovery",
	"/compute/v2.1/":                 "nova_api_v2.1",
	"/compute/os-services":           "nova_os_services",
	"/compute/os-hypervisors/detail": "nova_os_hypervisors",
	"/compute/flavors/detail":        "nova_os_flavors",
	"/compute/os-availability-zone":  "nova_os_availability_zones",
	"/compute/os-security-groups":    "nova_os_security_groups",
	"/compute/os-aggregates":         "nova_os_aggregates",
	"/compute/limits?tenant_id=0c4e939acacf4376bdcd1129f1a054ad": "nova_os_limits",
	"/compute/limits?tenant_id=0cbd49cbf76d405d9c86562e1d579bd3": "nova_os_limits",
	"/compute/limits?tenant_id=2db68fed84324f29bb73130c6c2094fb": "nova_os_limits",
	"/compute/limits?tenant_id=3d594eb0f04741069dbbb521635b21c7": "nova_os_limits",
	"/compute/limits?tenant_id=43ebde53fc314b1c9ea2b8c5dc744927": "nova_os_limits",
	"/compute/limits?tenant_id=4b1eb781a47440acb8af9850103e537f": "nova_os_limits",
	"/compute/limits?tenant_id=5961c443439d4fcebe42643723755e9d": "nova_os_limits",
	"/compute/limits?tenant_id=fdb8424c4e4f4c0ba32c52e2de3bd80e": "nova_os_limits",
	"/compute/servers/detail?all_tenants=true":                   "nova_os_servers",
	"/compute/os-simple-tenant-usage?detailed=1":                 "nova_os_simple_tenant_usage",
	"/glance/":          "glance_api_discovery",
	"/glance/v2/images": "glance_images",
	"/gnocchi/v1/metric?marker=5e9b3ee0-aee1-4461-8849-3f4ae5e30d8d": "gnocchi_empty",
	"/gnocchi/v1/metric":                         "gnocchi_metric",
	"/gnocchi/v1/status":                         "gnocchi_status",
	"/gnocchi/v1/status?details=true":            "gnocchi_status",
	"/identity/v3/projects":                      "identity_projects",
	"/identity/v3/domains":                       "identity_domains",
	"/identity/v3/users":                         "identity_users",
	"/identity/v3/groups":                        "identity_groups",
	"/identity/v3/regions":                       "identity_regions",
	"/neutron/":                                  "neutron_api_discovery",
	"/neutron/v2.0/floatingips":                  "neutron_floating_ips",
	"/neutron/v2.0/agents":                       "neutron_agents",
	"/neutron/v2.0/networks":                     "neutron_networks",
	"/neutron/v2.0/security-groups":              "neutron_security_groups",
	"/neutron/v2.0/subnets":                      "neutron_subnets",
	"/neutron/v2.0/subnetpools":                  "neutron_subnet_pools",
	"/neutron/v2.0/ports":                        "neutron_ports",
	"/neutron/v2.0/network-ip-availabilities":    "neutron_network_ip_availabilities",
	"/neutron/v2.0/routers":                      "neutron_routers",
	"/neutron/v2.0/agents?binary=ovn-controller": "neutron_ovn_controller_agents",
	"/neutron/v2.0/routers/f8a44de0-fc8e-45df-93c7-f79bf3b01c95/l3-agents": "neutron_routers_l3_agents",
	"/neutron/v2.0/routers/9daeb7dd-7e3f-4e44-8c42-c7a0e8c8a42f/l3-agents": "neutron_routers_l3_agents",
	"/neutron/v2.0/vpn/endpoint-groups":                                    "neutron_vpn_endpoint_groups",
	"/neutron/v2.0/vpn/ipsecpolicies":                                      "neutron_ipsecpolicies",
	"/neutron/v2.0/vpn/vpnservices":                                        "neutron_vpnservices",
	"/neutron/v2.0/vpn/ipsec-site-connections":                             "neutron_ipsec_site_connections",
	"/neutron/v2.0/vpn/ikepolicies":                                        "neutron_ikepolicies",
	"/loadbalancer/":                                                       "loadbalancer_api_discovery",
	"/loadbalancer/v2.0/lbaas/loadbalancers":                               "loadbalancer_loadbalancers",
	"/loadbalancer/v2.0/octavia/amphorae":                                  "loadbalancer_amphorae",
	"/loadbalancer/v2.0/lbaas/pools":                                       "loadbalancer_pools",
	"/ironic/":                                                             "ironic_api_discovery",
	"/ironic/v1":                                                           "ironic_v1",
	"/ironic/v1/nodes":                                                     "ironic_nodes",
	"/ironic/v1/nodes/detail?limit=1000&sort_dir=asc&sort_key=id":          "ironic_nodes",
	"/ironic/v1/nodes/detail?limit=1000&marker=0129d2fc-0e5c-4b5b-a73b-01844d913957&sort_dir=asc&sort_key=id": "ironic_nodes_empty",
	"/volumes":  "cinder_api_discovery",
	"/volumes/": "cinder_api_discovery",
	"/volumes/volumes/detail?all_tenants=true":                           "cinder_volumes",
	"/volumes/snapshots/detail":                                          "cinder_snapshots",
	"/volumes/backups/detail":                                            "cinder_backups",
	"/volumes/os-services":                                               "cinder_os_services",
	"/volumes/scheduler-stats/get_pools?detail=true":                     "cinder_scheduler_stats_pools",
	"/volumes/os-quota-sets/0c4e939acacf4376bdcd1129f1a054ad?usage=true": "cinder_os_quota_sets_usage",
	"/volumes/os-quota-sets/0cbd49cbf76d405d9c86562e1d579bd3?usage=true": "cinder_os_quota_sets_usage",
	"/volumes/os-quota-sets/2db68fed84324f29bb73130c6c2094fb?usage=true": "cinder_os_quota_sets_usage",
	"/volumes/os-quota-sets/3d594eb0f04741069dbbb521635b21c7?usage=true": "cinder_os_quota_sets_usage",
	"/volumes/os-quota-sets/43ebde53fc314b1c9ea2b8c5dc744927?usage=true": "cinder_os_quota_sets_usage",
	"/volumes/os-quota-sets/4b1eb781a47440acb8af9850103e537f?usage=true": "cinder_os_quota_sets_usage",
	"/volumes/os-quota-sets/5961c443439d4fcebe42643723755e9d?usage=true": "cinder_os_quota_sets_usage",
	"/volumes/os-quota-sets/fdb8424c4e4f4c0ba32c52e2de3bd80e?usage=true": "cinder_os_quota_sets_usage",
	"/volumes/os-quota-sets/0c4e939acacf4376bdcd1129f1a054ad":            "cinder_os_quota_sets",
	"/volumes/os-quota-sets/0cbd49cbf76d405d9c86562e1d579bd3":            "cinder_os_quota_sets",
	"/volumes/os-quota-sets/2db68fed84324f29bb73130c6c2094fb":            "cinder_os_quota_sets",
	"/volumes/os-quota-sets/3d594eb0f04741069dbbb521635b21c7":            "cinder_os_quota_sets",
	"/volumes/os-quota-sets/43ebde53fc314b1c9ea2b8c5dc744927":            "cinder_os_quota_sets",
	"/volumes/os-quota-sets/4b1eb781a47440acb8af9850103e537f":            "cinder_os_quota_sets",
	"/volumes/os-quota-sets/5961c443439d4fcebe42643723755e9d":            "cinder_os_quota_sets",
	"/volumes/os-quota-sets/fdb8424c4e4f4c0ba32c52e2de3bd80e":            "cinder_os_quota_sets",
	"/designate/":         "designate_api_discovery",
	"/designate/v2/zones": "designate_zones",
	"/designate/v2/zones/a86dba58-0043-4cc6-a1bb-69d5e86f3ca3/recordsets": "designate_recordsets",
	"/database/": "trove_api_discovery",
	"/database/mgmt/instances?include_clustered=False&deleted=False": "trove_instances",
	"/orchestration/":               "heat_api_discovery",
	"/orchestration/stacks":         "heat_stacks",
	"/placement/":                   "placement_api_discovery",
	"/placement/resource_providers": "resource_providers",
	"/placement/resource_providers/b985be15-99bf-4baf-9ef7-3ef166cd7f31/inventories": "resource_provider_1_inventory",
	"/placement/resource_providers/328c9f0a-5a3c-4ad6-9347-689eb7632d7b/inventories": "resource_provider_2_inventory",
	"/placement/resource_providers/b985be15-99bf-4baf-9ef7-3ef166cd7f31/usages":      "resource_provider_1_usage",
	"/placement/resource_providers/328c9f0a-5a3c-4ad6-9347-689eb7632d7b/usages":      "resource_provider_2_usage",
	"/placement/resource_providers/b985be15-99bf-4baf-9ef7-3ef166cd7f31/allocations": "resource_provider_1_allocations",
	"/placement/resource_providers/328c9f0a-5a3c-4ad6-9347-689eb7632d7b/allocations": "resource_provider_2_allocations",
	"/compute/os-quota-sets/0c4e939acacf4376bdcd1129f1a054ad/detail":                 "nova_quotas_1_usage",
	"/compute/os-quota-sets/0cbd49cbf76d405d9c86562e1d579bd3/detail":                 "nova_quotas_1_usage",
	"/compute/os-quota-sets/2db68fed84324f29bb73130c6c2094fb/detail":                 "nova_quotas_1_usage",
	"/compute/os-quota-sets/3d594eb0f04741069dbbb521635b21c7/detail":                 "nova_quotas_1_usage",
	"/compute/os-quota-sets/43ebde53fc314b1c9ea2b8c5dc744927/detail":                 "nova_quotas_1_usage",
	"/compute/os-quota-sets/5961c443439d4fcebe42643723755e9d/detail":                 "nova_quotas_1_usage",
	"/compute/os-quota-sets/fdb8424c4e4f4c0ba32c52e2de3bd80e/detail":                 "nova_quotas_1_usage",
	"/compute/os-quota-sets/4b1eb781a47440acb8af9850103e537f/detail":                 "nova_quotas_1_usage",
	"/neutron/v2.0/quotas/0c4e939acacf4376bdcd1129f1a054ad/details.json":             "neutron_quotas_1_usage",
	"/neutron/v2.0/quotas/0cbd49cbf76d405d9c86562e1d579bd3/details.json":             "neutron_quotas_1_usage",
	"/neutron/v2.0/quotas/2db68fed84324f29bb73130c6c2094fb/details.json":             "neutron_quotas_1_usage",
	"/neutron/v2.0/quotas/3d594eb0f04741069dbbb521635b21c7/details.json":             "neutron_quotas_1_usage",
	"/neutron/v2.0/quotas/43ebde53fc314b1c9ea2b8c5dc744927/details.json":             "neutron_quotas_1_usage",
	"/neutron/v2.0/quotas/5961c443439d4fcebe42643723755e9d/details.json":             "neutron_quotas_1_usage",
	"/neutron/v2.0/quotas/fdb8424c4e4f4c0ba32c52e2de3bd80e/details.json":             "neutron_quotas_1_usage",
	"/neutron/v2.0/quotas/4b1eb781a47440acb8af9850103e537f/details.json":             "neutron_quotas_1_usage",
	"/shares/v2/shares/detail?all_tenants=true":                                      "manila_shares",
	"/object-store/": "swift_list", // NOTE: /v1/AUTH_%(tenant_id)s
	"/object-store/?marker=centos9-epel-next": "swift_empty",
}

const DEFAULT_UUID = "3649e0f6-de80-ab6e-4f1c-351042d2f7fe"

func (suite *BaseOpenStackTestSuite) SetupTest() {
	httpmock.Activate()
	suite.Prefix = "openstack"

	suite.teardownFixtures()
	suite.installFixtures()

	os.Setenv("OS_CLIENT_CONFIG_FILE", path.Join(baseFixturePath, "test_config.yaml"))

	novaMetadataMapping := new(utils.LabelMappingFlag)
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{}))
	exporter, err := NewExporter(suite.ServiceName, suite.Prefix, cloudName, []string{}, "public", false, false, false, false, "", "", novaMetadataMapping, 10, func() (string, error) {
		return DEFAULT_UUID, nil
	}, logger)

	if err != nil {
		suite.Require().NoError(err)
	}
	suite.Exporter = &exporter
}

func (suite *BaseOpenStackTestSuite) teardownFixtures() {
	httpmock.Reset()
	suite.SetResponseFromFixture("POST", 201,
		suite.MakeURL("/v3/auth/tokens", "35357"),
		suite.FixturePath("tokens"),
	)
}

func (suite *BaseOpenStackTestSuite) installFixtures() {
	for path, fixture := range fixtures {
		suite.SetResponseFromFixture("GET", 200,
			suite.MakeURL(path, ""),
			suite.FixturePath(fixture),
		)
	}

	// NOTE(mnaser): The following makes sure that all requests are mocked
	//               and any un-mocked requests will fail to ensure we have
	//               full coverage.
	httpmock.RegisterNoResponder(
		func(req *http.Request) (*http.Response, error) {
			msg := fmt.Sprintf("Unmocked request: %s", req.URL.RequestURI())
			suite.T().Error(errors.New(msg))
			return httpmock.NewStringResponse(500, ""), nil
		},
	)
}

func (suite *BaseOpenStackTestSuite) TearDownTest() {
	defer httpmock.DeactivateAndReset()
}

func TestOpenStackSuites(t *testing.T) {
	suite.Run(t, &CinderTestSuite{BaseOpenStackTestSuite: BaseOpenStackTestSuite{ServiceName: "volume"}})
	suite.Run(t, &NovaTestSuite{BaseOpenStackTestSuite: BaseOpenStackTestSuite{ServiceName: "compute"}})
	suite.Run(t, &NeutronTestSuite{BaseOpenStackTestSuite: BaseOpenStackTestSuite{ServiceName: "network"}})
	suite.Run(t, &LoadbalancerTestSuite{BaseOpenStackTestSuite: BaseOpenStackTestSuite{ServiceName: "load-balancer"}})
	suite.Run(t, &GlanceTestSuite{BaseOpenStackTestSuite: BaseOpenStackTestSuite{ServiceName: "image"}})
	suite.Run(t, &ContainerInfraTestSuite{BaseOpenStackTestSuite: BaseOpenStackTestSuite{ServiceName: "container-infra"}})
	suite.Run(t, &DesignateTestSuite{BaseOpenStackTestSuite: BaseOpenStackTestSuite{ServiceName: "dns"}})
	suite.Run(t, &IronicTestSuite{BaseOpenStackTestSuite: BaseOpenStackTestSuite{ServiceName: "baremetal"}})
	suite.Run(t, &GnocchiTestSuite{BaseOpenStackTestSuite: BaseOpenStackTestSuite{ServiceName: "gnocchi"}})
	suite.Run(t, &KeystoneTestSuite{BaseOpenStackTestSuite: BaseOpenStackTestSuite{ServiceName: "identity"}})
	suite.Run(t, &TroveTestSuite{BaseOpenStackTestSuite: BaseOpenStackTestSuite{ServiceName: "database"}})
	suite.Run(t, &HeatTestSuite{BaseOpenStackTestSuite: BaseOpenStackTestSuite{ServiceName: "orchestration"}})
	suite.Run(t, &PlacementTestSuite{BaseOpenStackTestSuite: BaseOpenStackTestSuite{ServiceName: "placement"}})
	suite.Run(t, &ManilaTestSuite{BaseOpenStackTestSuite: BaseOpenStackTestSuite{ServiceName: "sharev2"}})
	suite.Run(t, &ObjectStoreTestSuite{BaseOpenStackTestSuite: BaseOpenStackTestSuite{ServiceName: "object-store"}})
}

func TestTransportFromCloudConfig(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	// The server's certificate serves as the CA and, with its key, as the client certificate.
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	caFile := writeTempFile(t, "ca.pem", caPEM)
	keyDER, err := x509.MarshalPKCS8PrivateKey(srv.TLS.Certificates[0].PrivateKey)
	require.NoError(t, err)
	keyFile := writeTempFile(t, "client.key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	badKeyFile := writeTempFile(t, "bad.key", []byte("not a key"))

	verifyTrue, verifyFalse := true, false

	reachesServer := func(t *testing.T, rt http.RoundTripper) {
		t.Helper()
		resp, err := (&http.Client{Transport: rt}).Get(srv.URL)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())
	}

	tests := []struct {
		name    string
		cloud   clientconfigv2.Cloud
		osDebug bool
		wantLog string
		check   func(t *testing.T, rt http.RoundTripper, err error)
	}{
		{
			// nil keeps the default transport, which httpmock intercepts in the exporter suites.
			name:  "no TLS settings returns nil",
			cloud: clientconfigv2.Cloud{Verify: &verifyTrue},
			check: func(t *testing.T, rt http.RoundTripper, err error) {
				require.NoError(t, err)
				assert.Nil(t, rt)
			},
		},
		{
			name:  "nil verify is treated as true",
			cloud: clientconfigv2.Cloud{},
			check: func(t *testing.T, rt http.RoundTripper, err error) {
				require.NoError(t, err)
				assert.Nil(t, rt)
			},
		},
		{
			name:    "verify false skips certificate verification",
			cloud:   clientconfigv2.Cloud{Verify: &verifyFalse},
			wantLog: "SSL verification disabled on transport",
			check: func(t *testing.T, rt http.RoundTripper, err error) {
				require.NoError(t, err)
				assert.True(t, tlsTransport(t, rt).TLSClientConfig.InsecureSkipVerify)
				reachesServer(t, rt)
			},
		},
		{
			name:  "cacert file is trusted",
			cloud: clientconfigv2.Cloud{Verify: &verifyTrue, CACertFile: caFile},
			check: func(t *testing.T, rt http.RoundTripper, err error) {
				require.NoError(t, err)
				want, _ := x509.SystemCertPool()
				if want == nil {
					want = x509.NewCertPool()
				}
				want.AppendCertsFromPEM(caPEM)
				assert.True(t, want.Equal(tlsTransport(t, rt).TLSClientConfig.RootCAs), "cacert adds to the system CAs")
				reachesServer(t, rt)
			},
		},
		{
			name:  "cacert PEM contents are trusted",
			cloud: clientconfigv2.Cloud{Verify: &verifyTrue, CACertFile: string(caPEM)},
			check: func(t *testing.T, rt http.RoundTripper, err error) {
				require.NoError(t, err)
				tlsTransport(t, rt)
				reachesServer(t, rt)
			},
		},
		{
			// Records existing behavior rather than endorsing it.
			name:    "unreadable cacert is logged and the system roots are used",
			cloud:   clientconfigv2.Cloud{Verify: &verifyTrue, CACertFile: filepath.Join(t.TempDir(), "missing.pem")},
			wantLog: "Failed to include additional certificates to ca-trust",
			check: func(t *testing.T, rt http.RoundTripper, err error) {
				require.NoError(t, err)
				assert.Nil(t, tlsTransport(t, rt).TLSClientConfig.RootCAs)
			},
		},
		{
			name:  "client cert and key are loaded",
			cloud: clientconfigv2.Cloud{Verify: &verifyTrue, ClientCertFile: caFile, ClientKeyFile: keyFile},
			check: func(t *testing.T, rt http.RoundTripper, err error) {
				require.NoError(t, err)
				certs := tlsTransport(t, rt).TLSClientConfig.Certificates
				require.Len(t, certs, 1)
				assert.Equal(t, srv.Certificate().Raw, certs[0].Certificate[0])
			},
		},
		{
			name:  "invalid client key returns an error",
			cloud: clientconfigv2.Cloud{Verify: &verifyTrue, ClientCertFile: caFile, ClientKeyFile: badKeyFile},
			check: func(t *testing.T, rt http.RoundTripper, err error) {
				require.Error(t, err)
				assert.Nil(t, rt)
			},
		},
		{
			name:    "OS_DEBUG wraps the transport in a request logger",
			cloud:   clientconfigv2.Cloud{Verify: &verifyTrue},
			osDebug: true,
			check: func(t *testing.T, rt http.RoundTripper, err error) {
				require.NoError(t, err)
				assert.IsType(t, &clientutilsv2.RoundTripper{}, rt)
			},
		},
		{
			// AuthenticatedClientV2 can't set the proxy through the OS_DEBUG wrapper.
			name:    "OS_DEBUG with TLS settings keeps the proxy",
			cloud:   clientconfigv2.Cloud{Verify: &verifyTrue, CACertFile: caFile},
			osDebug: true,
			check: func(t *testing.T, rt http.RoundTripper, err error) {
				require.NoError(t, err)
				require.IsType(t, &clientutilsv2.RoundTripper{}, rt)
				tlsTransport(t, rt)
				reachesServer(t, rt)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("OS_DEBUG", "1")
			if !tc.osDebug {
				require.NoError(t, os.Unsetenv("OS_DEBUG"))
			}

			var logs bytes.Buffer
			rt, err := transportFromCloudConfig(&tc.cloud, slog.New(slog.NewTextHandler(&logs, nil)))
			tc.check(t, rt, err)
			if tc.wantLog != "" {
				assert.Contains(t, logs.String(), tc.wantLog)
			}
		})
	}
}

func TestTransportFromCloudConfigWithReplacedDefaultTransport(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()
	t.Setenv("OS_DEBUG", "")
	require.NoError(t, os.Unsetenv("OS_DEBUG"))

	verifyFalse := false
	rt, err := transportFromCloudConfig(&clientconfigv2.Cloud{Verify: &verifyFalse}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)

	// The fallback keeps the previous behavior plus the proxy.
	tr, ok := rt.(*http.Transport)
	require.True(t, ok, "expected *http.Transport, got %T", rt)
	assert.True(t, tr.TLSClientConfig.InsecureSkipVerify)
	assert.NotNil(t, tr.Proxy, "proxy from environment")
	assert.False(t, tr.ForceAttemptHTTP2, "HTTP/2 stays off")
}

// tlsTransport unwraps the OS_DEBUG logger and checks that the default transport's settings were kept.
func tlsTransport(t *testing.T, rt http.RoundTripper) *http.Transport {
	t.Helper()
	if debug, ok := rt.(*clientutilsv2.RoundTripper); ok {
		rt = debug.Rt
	}
	tr, ok := rt.(*http.Transport)
	require.True(t, ok, "expected *http.Transport, got %T", rt)
	require.NotNil(t, tr.TLSClientConfig)
	assert.NotNil(t, tr.Proxy, "proxy from environment")
	assert.Positive(t, tr.TLSHandshakeTimeout, "TLS handshake timeout")
	assert.False(t, tr.ForceAttemptHTTP2, "HTTP/2 stays off")
	return tr
}

func writeTempFile(t *testing.T, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	require.NoError(t, os.WriteFile(path, data, 0o600))
	return path
}
