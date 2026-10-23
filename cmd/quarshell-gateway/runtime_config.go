package main

import (
	"encoding/json"
	"fmt"

	"github.com/KLORQ/quarshell-gateway/internal/gatewayconfig"
)

// resolveRuntimeConfig applies the pinned OpenShell Gateway TOML driver table,
// then lets the explicit runtime flags override it. The driver table remains
// operator-owned; it is not sourced from sandbox create requests.
func resolveRuntimeConfig(configPath, runtimeConfigJSON, runtimeName string, runtimeExplicit bool) (string, map[string]any, error) {
	config := make(map[string]any)
	path, found, err := gatewayconfig.SelectPath(configPath)
	if err != nil {
		return "", nil, fmt.Errorf("select gateway config: %w", err)
	}
	if found {
		file, err := gatewayconfig.Load(path)
		if err != nil {
			return "", nil, err
		}
		if !runtimeExplicit && file.OpenShell.Gateway.ComputeDriver != nil {
			runtimeName = *file.OpenShell.Gateway.ComputeDriver
		}
		for key, value := range file.DriverTable(runtimeName) {
			config[key] = value
		}
	}
	var overrides map[string]any
	if err := json.Unmarshal([]byte(runtimeConfigJSON), &overrides); err != nil {
		return "", nil, fmt.Errorf("runtime-config: %w", err)
	}
	for key, value := range overrides {
		config[key] = value
	}
	return runtimeName, config, nil
}
