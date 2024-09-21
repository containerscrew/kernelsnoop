package config

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
	Syscall struct {
		Enabled bool `toml:"enabled"`
		SysCalls []string `toml:"syscalls"`
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
