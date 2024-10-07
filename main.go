package main

import (
	"context"

	devstdout "github.com/containerscrew/devstdout/pkg"
	"github.com/containerscrew/kernelsnoop/internal/config"
	ksnoop_tcp_connect "github.com/containerscrew/kernelsnoop/internal/ksnoop/tcp_connect"
)

func main() {
	// Read config file
	config, err := config.ReadConfigFile()
	if err != nil {
		panic(err)
	}

	log := devstdout.NewLogger(
		devstdout.OptionsLogger{Level: config.Log.Level, AddSource: false, LoggerType: config.Log.Type},
	)

	log.Info("Starting kernelsnoop")

	ctx := context.WithValue(context.Background(), "log", log)

	ksnoop_tcp_connect.TcpConnect(ctx)

	//ksnoop_file_permissions.FilePermissions(ctx)
}
