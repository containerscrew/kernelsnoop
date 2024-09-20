package utils

import (
	"context"

	logger "github.com/containerscrew/devstdout/pkg"
)

func GetLogger(ctx context.Context) *logger.CustomLogger {
	log, ok := ctx.Value("logger").(*logger.CustomLogger)
	if !ok {
		panic("no logger found in context")
	}

	return log
}
