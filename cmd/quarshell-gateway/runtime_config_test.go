package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveRuntimeConfigLoadsOpenShellVMTableAndMergesOverrides(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gateway.toml")
	contents := `[openshell.gateway]
compute_driver = "vm"
[openshell.drivers.vm]
default_image = "registry.example/bootstrap:v1"
vcpus = 4
`
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	name, config, err := resolveRuntimeConfig(path, `{"vcpus":6,"mem_mib":4096}`, "docker", false)
	if err != nil {
		t.Fatal(err)
	}
	if name != "vm" || config["default_image"] != "registry.example/bootstrap:v1" || config["vcpus"] != float64(6) || config["mem_mib"] != float64(4096) {
		t.Fatalf("runtime config name=%q values=%v", name, config)
	}
}

func TestResolveRuntimeConfigRejectsInvalidVMProxyConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gateway.toml")
	contents := `[openshell.gateway]
compute_driver = "vm"
[openshell.drivers.vm]
no_proxy = "10.0.0.0/8"
`
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err := resolveRuntimeConfig(path, `{}`, "docker", true)
	if err == nil || !strings.Contains(err.Error(), "no_proxy") || !strings.Contains(err.Error(), "https_proxy") {
		t.Fatalf("invalid VM proxy config error=%v", err)
	}
}

func TestResolveRuntimeConfigExplicitRuntimeChoosesItsDriverTable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gateway.toml")
	contents := `[openshell.gateway]
compute_driver = "vm"
[openshell.drivers.vm]
default_image = "vm-image"
[openshell.drivers.docker]
rootless = true
`
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	name, config, err := resolveRuntimeConfig(path, `{}`, "docker", true)
	if err != nil {
		t.Fatal(err)
	}
	if name != "docker" || config["rootless"] != true || config["default_image"] != nil {
		t.Fatalf("explicit runtime config name=%q values=%v", name, config)
	}
}
