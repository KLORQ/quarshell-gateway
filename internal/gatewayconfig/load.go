package gatewayconfig

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

const MaxFileBytes = 1 << 20

// SelectPath follows the pinned config flag > env > optional XDG search order.
// Explicit paths must exist; an absent implicit file is equivalent to no file.
func SelectPath(flagPath string) (string, bool, error) {
	path := flagPath
	if path == "" {
		if selected, present := os.LookupEnv("OPENSHELL_GATEWAY_CONFIG"); present {
			return selected, true, nil
		}
	}
	if path != "" {
		return path, true, nil
	}
	dir, present := os.LookupEnv("XDG_CONFIG_HOME")
	if !present && runtime.GOOS == "windows" {
		dir, present = os.LookupEnv("APPDATA")
	}
	if !present {
		home, present := os.LookupEnv("HOME")
		if !present {
			return "", false, fmt.Errorf("gateway config: HOME is not set")
		}
		dir = filepath.Join(home, ".config")
	}
	path = filepath.Join(dir, "openshell", "gateway.toml")
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return "", false, nil
		}
		return "", false, err
	}
	return path, true, nil
}

func Load(path string) (File, error) {
	input, err := os.Open(path)
	if err != nil {
		return File{}, fmt.Errorf("gateway config: open: %w", err)
	}
	defer input.Close()
	data, err := io.ReadAll(io.LimitReader(input, MaxFileBytes+1))
	if err != nil {
		return File{}, fmt.Errorf("gateway config: read: %w", err)
	}
	return Parse(data)
}

func Parse(data []byte) (File, error) {
	if len(data) > MaxFileBytes {
		return File{}, fmt.Errorf("gateway config exceeds %d byte limit", MaxFileBytes)
	}
	var file File
	err := toml.NewDecoder(bytes.NewReader(data)).DisallowUnknownFields().Decode(&file)
	if err != nil {
		var unknown *toml.StrictMissingError
		if errors.As(err, &unknown) {
			keys := make([]string, 0, len(unknown.Errors))
			for _, field := range unknown.Errors {
				keys = append(keys, strings.Join(field.Key(), "."))
			}
			return File{}, fmt.Errorf("gateway config: unknown fields: %s", strings.Join(keys, ", "))
		}
		var decode *toml.DecodeError
		if errors.As(err, &decode) {
			line, column := decode.Position()
			return File{}, fmt.Errorf("gateway config: invalid TOML at line %d column %d (field %s)", line, column, strings.Join(decode.Key(), "."))
		}
		return File{}, fmt.Errorf("gateway config: invalid TOML")
	}
	if err := file.validate(); err != nil {
		return File{}, err
	}
	rawTables := []any{file.OpenShell.Drivers, file.OpenShell.CredentialDrivers}
	if file.OpenShell.Gateway.CredentialStorage != nil {
		rawTables = append(rawTables, *file.OpenShell.Gateway.CredentialStorage)
	}
	for _, raw := range rawTables {
		if err := validateRawDepth(raw); err != nil {
			return File{}, err
		}
	}
	if raw, ok := file.OpenShell.Drivers["vm"].(map[string]any); ok {
		if err := validateVMProxyConfig(raw); err != nil {
			return File{}, fmt.Errorf("gateway config: openshell.drivers.vm: %w", err)
		}
	}
	return file, nil
}

// validateVMProxyConfig mirrors the cross-field safety contract of the pinned
// OpenShell VM driver. Keep values out of errors because proxy URLs and paths
// can contain operator-sensitive data.
func validateVMProxyConfig(config map[string]any) error {
	proxyURL, hasProxy := config["https_proxy"]
	proxy := ""
	proxyScheme := ""
	if hasProxy {
		var ok bool
		proxy, ok = proxyURL.(string)
		if !ok || strings.TrimSpace(proxy) == "" {
			return fmt.Errorf("https_proxy must be a non-empty URL when set")
		}
		parsed, err := url.Parse(proxy)
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil || parsed.Opaque != "" || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
			return fmt.Errorf("https_proxy must be an http(s) proxy URL without credentials, path, query or fragment")
		}
		proxyScheme = parsed.Scheme
	}
	if raw, exists := config["no_proxy"]; exists {
		value, ok := raw.(string)
		if !ok || strings.TrimSpace(value) == "" {
			return fmt.Errorf("no_proxy must be non-empty when set")
		}
		if !hasProxy {
			return fmt.Errorf("no_proxy is set but no https_proxy is configured")
		}
	}
	if raw, exists := config["proxy_auth_file"]; exists {
		path, ok := raw.(string)
		if !ok || strings.TrimSpace(path) == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return fmt.Errorf("proxy_auth_file must be a non-empty absolute clean path")
		}
		if !hasProxy {
			return fmt.Errorf("proxy_auth_file is set but no https_proxy is configured")
		}
		if insecure, configured := config["proxy_auth_allow_insecure"]; configured {
			allow, valid := insecure.(bool)
			if !valid {
				return fmt.Errorf("proxy_auth_allow_insecure must be a boolean")
			}
			if proxyScheme == "http" && !allow {
				return fmt.Errorf("proxy_auth_allow_insecure must be true for Basic auth over an http proxy")
			}
		} else if proxyScheme == "http" {
			return fmt.Errorf("proxy_auth_file with an http proxy requires proxy_auth_allow_insecure=true")
		}
	} else if _, configured := config["proxy_auth_allow_insecure"]; configured {
		return fmt.Errorf("proxy_auth_allow_insecure is set but no proxy_auth_file is configured")
	}
	if value, exists := config["proxy_connect_by_hostname"]; exists {
		_, ok := value.(bool)
		if !ok {
			return fmt.Errorf("proxy_connect_by_hostname must be a boolean")
		}
		if !hasProxy {
			return fmt.Errorf("proxy_connect_by_hostname is set but no https_proxy is configured")
		}
	}
	if raw, exists := config["proxy_ca_bundle"]; exists {
		path, ok := raw.(string)
		if !ok || strings.TrimSpace(path) == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return fmt.Errorf("proxy_ca_bundle must be a non-empty absolute clean path")
		}
		if !hasProxy {
			return fmt.Errorf("proxy_ca_bundle is set but no https_proxy is configured")
		}
	}
	if rawEndpoint, configured := config["provider_spiffe_workload_api_tcp_endpoint"]; configured {
		endpoint, ok := rawEndpoint.(string)
		if !ok || endpoint == "" || strings.TrimSpace(endpoint) != endpoint || !strings.HasPrefix(endpoint, "tcp:") {
			return fmt.Errorf("provider_spiffe_workload_api_tcp_endpoint must use tcp:IP:port without surrounding whitespace")
		}
		acknowledged, ok := config["provider_spiffe_allow_guest_tcp"].(bool)
		if !ok || !acknowledged {
			return fmt.Errorf("provider_spiffe_workload_api_tcp_endpoint exposes the Workload API; set provider_spiffe_allow_guest_tcp=true to acknowledge guest access")
		}
		address, err := netip.ParseAddrPort(strings.TrimPrefix(endpoint, "tcp:"))
		if err != nil || address.Port() == 0 || address.Addr().IsUnspecified() {
			return fmt.Errorf("provider_spiffe_workload_api_tcp_endpoint must use a concrete IP address and non-zero port")
		}
	} else if acknowledged, configured := config["provider_spiffe_allow_guest_tcp"]; configured {
		allow, ok := acknowledged.(bool)
		if !ok {
			return fmt.Errorf("provider_spiffe_allow_guest_tcp must be a boolean")
		}
		if allow {
			return fmt.Errorf("provider_spiffe_allow_guest_tcp is set but no provider_spiffe_workload_api_tcp_endpoint is configured")
		}
	}
	return nil
}

// ValidateVMDriverProxyConfig validates an operator-owned VM driver table.
// It is exported for the Gateway request builder, which also accepts Options
// values that did not originate in a parsed TOML file.
func ValidateVMDriverProxyConfig(config map[string]any) error {
	return validateVMProxyConfig(config)
}

func required(path string, fields map[string]bool) error {
	keys := make([]string, 0, len(fields))
	for key, present := range fields {
		if !present {
			keys = append(keys, path+"."+key)
		}
	}
	if len(keys) == 0 {
		return nil
	}
	sort.Strings(keys)
	return fmt.Errorf("gateway config: required fields missing: %s", strings.Join(keys, ", "))
}

func (file *File) validate() error {
	root := &file.OpenShell
	g := &root.Gateway
	if root.Version != nil && *root.Version != 1 && *root.Version != 2 {
		return fmt.Errorf("gateway config: unsupported openshell.version (supported versions: 1, 2)")
	}
	if g.DatabaseURL != nil {
		return fmt.Errorf("gateway config: database_url is env/CLI-only; use OPENSHELL_DB_URL or --db-url")
	}
	if g.CredentialDrivers != nil && len(*g.CredentialDrivers) == 0 {
		return fmt.Errorf("gateway config: openshell.gateway.credential_drivers must be omitted or select an external driver")
	}
	if g.ComputeDriver != nil && strings.TrimSpace(*g.ComputeDriver) == "" {
		return fmt.Errorf("gateway config: compute_driver must be non-empty")
	}
	for key, addr := range map[string]*string{"bind_address": g.BindAddress, "health_bind_address": g.HealthBindAddress, "metrics_bind_address": g.MetricsBindAddress} {
		if addr != nil {
			if _, err := netip.ParseAddrPort(*addr); err != nil {
				return fmt.Errorf("gateway config: openshell.gateway.%s must be an IP socket address", key)
			}
		}
	}
	if g.PolicyValidationFailureMode != nil && *g.PolicyValidationFailureMode != "fail_closed" && *g.PolicyValidationFailureMode != "retain_last_valid" {
		return fmt.Errorf("gateway config: invalid openshell.gateway.policy_validation_failure_mode")
	}
	if t := g.TLS; t != nil {
		if err := required("openshell.gateway.tls", map[string]bool{"cert_path": t.CertPath != nil, "key_path": t.KeyPath != nil}); err != nil {
			return err
		}
	}
	if oidc := g.OIDC; oidc != nil {
		if err := required("openshell.gateway.oidc", map[string]bool{"issuer": oidc.Issuer != nil, "audience": oidc.Audience != nil}); err != nil {
			return err
		}
		if oidc.JWKSTTLSecs == nil {
			value := uint64(3600)
			oidc.JWKSTTLSecs = &value
		}
		for target, fallback := range map[**string]string{&oidc.RolesClaim: "realm_access.roles", &oidc.AdminRole: "openshell-admin", &oidc.UserRole: "openshell-user"} {
			if *target == nil {
				value := fallback
				*target = &value
			}
		}
	}
	if jwt := g.GatewayJWT; jwt != nil {
		if err := required("openshell.gateway.gateway_jwt", map[string]bool{"signing_key_path": jwt.SigningKeyPath != nil, "public_key_path": jwt.PublicKeyPath != nil, "kid_path": jwt.KIDPath != nil}); err != nil {
			return err
		}
		if jwt.GatewayID == nil {
			value := "openshell"
			jwt.GatewayID = &value
		}
	}
	if otlp := g.OTLP; otlp != nil {
		if err := required("openshell.gateway.otlp", map[string]bool{"endpoint": otlp.Endpoint != nil}); err != nil {
			return err
		}
	}
	if g.ProviderProfileSources != nil {
		if len(*g.ProviderProfileSources) == 0 {
			return fmt.Errorf("gateway config: openshell.gateway.provider_profile_sources must not be empty")
		}
		seen := map[string]struct{}{}
		for i, source := range *g.ProviderProfileSources {
			if source.Type == "builtin" {
				return fmt.Errorf("gateway config: provider profile source type \"builtin\" was removed; use user or interceptor")
			}
			valid := source.Type == "user" && source.Name == nil || source.Type == "interceptor" && source.Name != nil
			if !valid {
				return fmt.Errorf("gateway config: invalid openshell.gateway.provider_profile_sources[%d]", i)
			}
			id := source.Type
			if source.Name != nil {
				if strings.TrimSpace(*source.Name) == "" {
					return fmt.Errorf("gateway config: provider profile source name must not be empty")
				}
				id += ":" + *source.Name
			}
			if _, duplicate := seen[id]; duplicate {
				return fmt.Errorf("gateway config: duplicate provider profile source %q", id)
			}
			seen[id] = struct{}{}
		}
	}
	for i := range root.Supervisor.Middleware {
		m := &root.Supervisor.Middleware[i]
		if err := required(fmt.Sprintf("openshell.supervisor.middleware[%d]", i), map[string]bool{"name": m.Name != nil, "grpc_endpoint": m.GRPCEndpoint != nil, "max_payload_bytes": m.MaxPayloadBytes != nil}); err != nil {
			return err
		}
	}
	for i := range g.Interceptors {
		interceptor := &g.Interceptors[i]
		if err := required(fmt.Sprintf("openshell.gateway.interceptors[%d]", i), map[string]bool{"name": interceptor.Name != nil, "grpc_endpoint": interceptor.GRPCEndpoint != nil}); err != nil {
			return err
		}
		if interceptor.BindingPolicy != nil && *interceptor.BindingPolicy != "dynamic" && *interceptor.BindingPolicy != "allowlist" && *interceptor.BindingPolicy != "exact" {
			return fmt.Errorf("gateway config: invalid interceptor binding_policy")
		}
		if interceptor.BindingPolicy == nil {
			value := "dynamic"
			interceptor.BindingPolicy = &value
		}
		if err := failurePolicy(interceptor.FailurePolicy); err != nil {
			return err
		}
		for _, binding := range interceptor.Bindings {
			if err := failurePolicy(binding.FailurePolicy); err != nil {
				return err
			}
			if binding.Phases != nil {
				for _, phase := range *binding.Phases {
					if phase != "modify_operation" && phase != "validate" && phase != "post_commit" {
						return fmt.Errorf("gateway config: invalid interceptor phase")
					}
				}
			}
		}
	}
	return nil
}

func failurePolicy(value *string) error {
	if value != nil && *value != "fail_closed" && *value != "fail_open" {
		return fmt.Errorf("gateway config: invalid interceptor failure_policy")
	}
	return nil
}

// DriverTable returns a deep copy of one driver-owned table. Gateway-level
// inheritance was removed in the pinned OpenShell version; each backend reads
// only its own [openshell.drivers.<name>] table.
func (file File) DriverTable(name string) map[string]any {
	result := map[string]any{}
	if raw, ok := file.OpenShell.Drivers[name].(map[string]any); ok {
		for key, value := range raw {
			result[key] = cloneValue(value)
		}
	}
	return result
}

func cloneValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		result := make(map[string]any, len(typed))
		for key, item := range typed {
			result[key] = cloneValue(item)
		}
		return result
	case []any:
		result := make([]any, len(typed))
		for i, item := range typed {
			result[i] = cloneValue(item)
		}
		return result
	default:
		return value
	}
}

func validateRawDepth(value any) error {
	type item struct {
		value any
		depth int
	}
	queue := []item{{value, 0}}
	for len(queue) > 0 {
		last := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		if last.depth > 64 {
			return fmt.Errorf("gateway config: raw table nesting exceeds 64 levels")
		}
		switch typed := last.value.(type) {
		case map[string]any:
			for _, child := range typed {
				queue = append(queue, item{child, last.depth + 1})
			}
		case []any:
			for _, child := range typed {
				queue = append(queue, item{child, last.depth + 1})
			}
		}
	}
	return nil
}
