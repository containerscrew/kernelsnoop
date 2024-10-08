package main

import (
	"context"
	"fmt"

	devstdout "github.com/containerscrew/devstdout/pkg"
	"github.com/containerscrew/kernelsnoop/internal/config"
	"github.com/containerscrew/kernelsnoop/internal/core"
	"github.com/containerscrew/kernelsnoop/internal/programs/net_track"
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

	// Reset memory lock limit
	if err := core.RemoveMemLock(ctx); err != nil {
		log.Error(fmt.Sprintf("failed to remove memlock rlimit: %v. Consider using sudo or give necessary capabilities to the program", err))
	}

	net_track.NetworkTrack(ctx)
	//ksnoop_file_permissions.FilePermissions(ctx)
}
