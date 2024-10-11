package dto

import devstdout "github.com/containerscrew/devstdout/pkg"

type ContextData struct {
    Log    *devstdout.CustomLogger
    Config *Config
}
