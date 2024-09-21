package main

import (
	logger "github.com/containerscrew/devstdout/pkg"
	"github.com/containerscrew/kernelsnoop/internal/config"
	"github.com/containerscrew/kernelsnoop/internal/ebpftools"
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

	// ctx := context.WithValue(context.Background(), "logger", log)

	// Here I need to start the NewEbpfLoader(ctx) function and pass the ctx as an argument, and the C code will use to load and inject
	ebpftools.NewHelloWorld()
}
