package dto

import (
	"io"
	"os"

	"github.com/pelletier/go-toml"
)

type Config struct {
	Log struct {
		Level string `toml:"level"`
		Type  string `toml:"type"`
	}
	Networking struct {
		Enable_udp_tracing bool `toml:"enable_udp_tracing"`
		Enable_tcp_tracing bool `toml:"enable_tcp_tracing"`
		Udp_filter_ports []string `toml:"udp_filter_ports"`
		Tcp_filter_ports []string `toml:"tcp_filter_ports"`
	}
}

func ReadConfigFile() (Config, error) {
	file, err := os.Open("config.toml")
	if err != nil {
		return Config{}, err
	}
	defer file.Close()

	var config Config

	b, err := io.ReadAll(file)
	if err != nil {
		return Config{}, err
	}

	err = toml.Unmarshal(b, &config)
	if err != nil {
		return Config{}, err
	}

	return config, nil
}
