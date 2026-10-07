package main

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v2"
)

// Config holds the exporter configuration loaded from exporter.yaml
type Config struct {
	ViciSocket      string `yaml:"vici_socket"`      // path to charon VICI socket
	ServerName      string `yaml:"server_name"`      // server name shown in sessions
	Debug           bool   `yaml:"debug"`            // true/false, default false
	RefreshInterval int    `yaml:"refresh_interval"` // in seconds, default 15
}

func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Set defaults if not specified
	if config.ViciSocket == "" {
		config.ViciSocket = "/var/run/charon.vici"
	}
	if config.ServerName == "" {
		config.ServerName = "strongswan-server"
	}
	if config.RefreshInterval <= 0 {
		config.RefreshInterval = 15
	}

	return &config, nil
}
