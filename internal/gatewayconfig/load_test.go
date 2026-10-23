package gatewayconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLegacyGatewayConfigFixtures(t *testing.T) {
	paths, err := filepath.Glob("testdata/openshell/*.toml")
	if err != nil || len(paths) != 4 {
		t.Fatalf("fixtures=%v err=%v", paths, err)
	}
	for _, path := range paths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			if _, err := Load(path); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPinnedV014GatewayConfigFixtures(t *testing.T) {
	for _, backend := range []string{"docker", "podman"} {
		path := filepath.Join("testdata", "openshell-v0.1.4", backend+".toml")
		t.Run(backend, func(t *testing.T) {
			file, err := Load(path)
			if err != nil {
				t.Fatal(err)
			}
			g := file.OpenShell.Gateway
			if file.OpenShell.Version == nil || *file.OpenShell.Version != 2 || g.ComputeDriver == nil || *g.ComputeDriver != backend {
				t.Fatalf("pinned v0.1.4 selector lost: version=%v gateway=%+v", file.OpenShell.Version, g)
			}
		})
	}
}

func TestGatewayTOMLContractAndBounds(t *testing.T) {
	for name, input := range map[string]string{
		"unknown-root":             "[unrecognized]\npassword='do-not-print'",
		"unknown-nested":           "[openshell.gateway.auth]\nunknown='do-not-print'",
		"duplicate":                "[openshell.gateway]\nname='one'\nname='do-not-print'",
		"future-version":           "[openshell]\nversion=3",
		"zero-version":             "[openshell]\nversion=0",
		"negative-version":         "[openshell]\nversion=-1",
		"secret-in-file":           "[openshell.gateway]\ndatabase_url='postgres://do-not-print'",
		"empty-credential-driver":  "[openshell.gateway]\ncredential_drivers=[]",
		"dns-bind":                 "[openshell.gateway]\nbind_address='localhost:8080'",
		"missing-tls":              "[openshell.gateway.tls]\ncert_path='cert.pem'",
		"missing-oidc":             "[openshell.gateway.oidc]\nissuer='https://idp.example'",
		"source-union":             "[openshell.gateway]\nprovider_profile_sources=[{type='builtin',name='extra'}]",
		"empty-profile-sources":    "[openshell.gateway]\nprovider_profile_sources=[]",
		"duplicate-profile-source": "[openshell.gateway]\nprovider_profile_sources=[{type='builtin'},{type='builtin'}]",
		"builtin-removed":          "[openshell.gateway]\nprovider_profile_sources=[{type='builtin'}]",
		"payload-alias-duplicate":  "[[openshell.supervisor.middleware]]\nname='guard'\ngrpc_endpoint='http://guard'\nmax_payload_bytes=10\nmax_body_bytes=20",
		"oversized":                strings.Repeat(" ", MaxFileBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(input))
			if err == nil {
				t.Fatal("invalid config accepted")
			}
			if strings.Contains(err.Error(), "do-not-print") {
				t.Fatalf("error exposed a config value: %v", err)
			}
		})
	}
	for _, input := range []string{"", "[openshell]\nversion=1", "[openshell]\nversion=2", "[openshell.gateway]\ncompute_driver='docker'", "[openshell.gateway]\nimage_preparation_timeout_seconds=30", "[openshell.gateway]\nprovider_profile_sources=[{type='user'}]", "[openshell.gateway]\nprovider_profile_sources=[{type='interceptor',name='ext'}]"} {
		if _, err := Parse([]byte(input)); err != nil {
			t.Fatalf("pinned-valid config failed: %v", err)
		}
	}
	for _, input := range []string{"[openshell.gateway]\ncompute_driver=''", "[openshell.gateway]\ncompute_drivers=['docker']", "[openshell.gateway]\nimage_preparation_timeout_seconds=-1", "[openshell.gateway]\nimage_preparation_timeout_seconds=4294967296"} {
		if _, err := Parse([]byte(input)); err == nil {
			t.Fatalf("invalid config was accepted: %q", input)
		}
	}
}

func TestGatewayNestedDefaultsAndDriverTables(t *testing.T) {
	file, err := Parse([]byte(`[openshell.gateway]
[openshell.gateway.oidc]
issuer="https://idp.example"
audience="cli"
[openshell.drivers.docker]
default_image="driver-image"
`))
	if err != nil {
		t.Fatal(err)
	}
	oidc := file.OpenShell.Gateway.OIDC
	if *oidc.JWKSTTLSecs != 3600 || *oidc.RolesClaim != "realm_access.roles" || *oidc.AdminRole != "openshell-admin" {
		t.Fatalf("OIDC defaults=%+v", oidc)
	}
	table := file.DriverTable("docker")
	if table["default_image"] != "driver-image" {
		t.Fatalf("driver table=%v", table)
	}
	if len(file.DriverTable("other")) != 0 {
		t.Fatal("undeclared driver table returned values")
	}
	for _, field := range []string{"default_image", "supervisor_image", "sandbox_namespace", "guest_tls_cert", "guest_tls_key"} {
		if _, err := Parse([]byte("[openshell.gateway]\n" + field + "='legacy'")); err == nil {
			t.Fatalf("legacy gateway field %s accepted", field)
		}
	}
}

func TestVMCorporateProxyConfigurationValidation(t *testing.T) {
	for name, table := range map[string]string{
		"bypass without proxy": `no_proxy = "10.0.0.0/8"`,
		"auth without proxy":   `proxy_auth_file = "/run/secrets/proxy-auth"`,
		"cleartext auth without acknowledgement": `https_proxy = "http://proxy.example:8080"
proxy_auth_file = "/run/secrets/proxy-auth"`,
		"CA without proxy": `proxy_ca_bundle = "/etc/ssl/corp.pem"`,
		"SPIFFE TCP endpoint without acknowledgement": `provider_spiffe_workload_api_tcp_endpoint = "tcp:192.0.2.10:8081"`,
		"SPIFFE acknowledgement without endpoint":     `provider_spiffe_allow_guest_tcp = true`,
		"SPIFFE endpoint requires concrete IP": `provider_spiffe_workload_api_tcp_endpoint = "tcp:spiffe.example:8081"
provider_spiffe_allow_guest_tcp = true`,
		"SPIFFE endpoint rejects wildcard IP": `provider_spiffe_workload_api_tcp_endpoint = "tcp:0.0.0.0:8081"
provider_spiffe_allow_guest_tcp = true`,
		"SPIFFE endpoint rejects port zero": `provider_spiffe_workload_api_tcp_endpoint = "tcp:192.0.2.10:0"
provider_spiffe_allow_guest_tcp = true`,
		"URL credentials": `https_proxy = "http://user:pass@proxy.example:8080"`,
		"relative auth path": `https_proxy = "https://proxy.example:8443"
proxy_auth_file = "proxy-auth"`,
		"relative CA path": `https_proxy = "https://proxy.example:8443"
proxy_ca_bundle = "corp.pem"`,
	} {
		t.Run(name, func(t *testing.T) {
			input := "[openshell.drivers.vm]\n" + table + "\n"
			_, err := Parse([]byte(input))
			if err == nil {
				t.Fatal("invalid VM proxy configuration was accepted")
			}
			if name == "bypass without proxy" && (!strings.Contains(err.Error(), "no_proxy") || !strings.Contains(err.Error(), "https_proxy")) {
				t.Fatalf("incoherent proxy error=%q; want both no_proxy and https_proxy", err)
			}
		})
	}
	for _, table := range []string{
		`https_proxy = "https://proxy.example:8443"
no_proxy = "10.0.0.0/8,.svc.cluster.local"
proxy_auth_file = "/run/secrets/proxy-auth"
proxy_ca_bundle = "/etc/ssl/corp.pem"`,
		`https_proxy = "http://proxy.example:8080"
proxy_auth_file = "/run/secrets/proxy-auth"
proxy_auth_allow_insecure = true`,
		`https_proxy = "https://proxy.example:8443"
proxy_connect_by_hostname = true`,
		`provider_spiffe_workload_api_tcp_endpoint = "tcp:192.0.2.10:8081"
provider_spiffe_allow_guest_tcp = true`,
	} {
		if _, err := Parse([]byte("[openshell.drivers.vm]\n" + table + "\n")); err != nil {
			t.Fatalf("valid VM proxy configuration rejected: %v", err)
		}
	}
}

func TestGatewayConfigPathSelection(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("OPENSHELL_GATEWAY_CONFIG", "")
	if err := os.Unsetenv("OPENSHELL_GATEWAY_CONFIG"); err != nil {
		t.Fatal(err)
	}
	if _, found, err := SelectPath(""); err != nil || found {
		t.Fatalf("absent implicit config: found=%v err=%v", found, err)
	}
	path := filepath.Join(dir, "openshell", "gateway.toml")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if selected, found, err := SelectPath(""); err != nil || !found || selected != path {
		t.Fatalf("implicit selection=%q found=%v err=%v", selected, found, err)
	}
	t.Setenv("OPENSHELL_GATEWAY_CONFIG", "env.toml")
	if selected, _, _ := SelectPath(""); selected != "env.toml" {
		t.Fatalf("env selection=%q", selected)
	}
	if selected, _, _ := SelectPath("flag.toml"); selected != "flag.toml" {
		t.Fatalf("flag selection=%q", selected)
	}
	t.Setenv("OPENSHELL_GATEWAY_CONFIG", "")
	if selected, found, err := SelectPath(""); err != nil || !found || selected != "" {
		t.Fatalf("explicit empty env path: selected=%q found=%v err=%v", selected, found, err)
	}
	if _, err := Load(""); err == nil {
		t.Fatal("explicit empty file path silently ignored")
	}
}

func TestRawTablesBoundedAndDriverTablesIsolated(t *testing.T) {
	for _, prefix := range []string{"openshell.drivers.docker", "openshell.credential_drivers.remote", "openshell.gateway.credential_storage"} {
		input := "[" + prefix + strings.Repeat(".nested", 66) + "]\nvalue=1"
		if _, err := Parse([]byte(input)); err == nil {
			t.Fatalf("deep raw table accepted: %s", prefix)
		}
	}
	file, err := Parse([]byte(`[openshell.gateway]
name="gateway"
[openshell.drivers.docker.options]
value="original"
`))
	if err != nil {
		t.Fatal(err)
	}
	table := file.DriverTable("docker")
	if _, inherited := table["name"]; inherited {
		t.Fatalf("gateway field leaked into driver table=%v", table)
	}
	table["options"].(map[string]any)["value"] = "changed"
	if file.DriverTable("docker")["options"].(map[string]any)["value"] != "original" {
		t.Fatal("driver table mutation changed source config")
	}
}
