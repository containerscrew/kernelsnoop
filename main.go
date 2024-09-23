package main

import (
	"context"

	logger "github.com/containerscrew/devstdout/pkg"
	"github.com/containerscrew/kernelsnoop/internal/config"
	"github.com/containerscrew/kernelsnoop/internal/ksnoop"
)

func main() {
	// Read config file
	config, err := config.ReadConfigFile()
	if err != nil {
		panic(err)
	}

	log := logger.NewLogger(
		logger.OptionsLogger{Level: config.Log.Level, AddSource: false, LoggerType: config.Log.Type},
	)

	log.Info("Starting kernelsnoop")

	ctx := context.WithValue(context.Background(), "log", log)

	ksnoop.ProcessMonitor(ctx)
}
