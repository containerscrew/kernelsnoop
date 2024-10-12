package dto

import devstdout "github.com/containerscrew/devstdout/pkg"

type ContextData struct {
	Log    *devstdout.CustomLogger
	Config *Config
}

// Define a custom key type to avoid string-based key issues
type contextKey string

const ContextDataKey = contextKey("contextData")
