package main

import (
	"context"
	"fmt"
	"net/http"

	devstdout "github.com/containerscrew/devstdout/pkg"
	"github.com/containerscrew/kernelsnoop/internal/core"
	"github.com/containerscrew/kernelsnoop/internal/dto"
	"github.com/containerscrew/kernelsnoop/internal/monitoring"
	nettrack "github.com/containerscrew/kernelsnoop/internal/trackers/net_track"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {
	// Read config file
	config, err := dto.ReadConfigFile()
	if err != nil {
		panic(err)
	}

	log := devstdout.NewLogger(
		devstdout.OptionsLogger{Level: config.Log.Level, AddSource: false, LoggerType: config.Log.Type},
	)

	log.Info("Starting kernelsnoop")

	// Create a struct to hold both log and config
	contextData := &dto.ContextData{
		Log:    log,
		Config: &config,
	}

	// Add the contextData struct to the context using the custom key
	ctx := context.WithValue(context.Background(), dto.ContextDataKey, contextData)

	// Reset memory lock limit
	if err := core.RemoveMemLock(); err != nil {
		log.Error(fmt.Sprintf("failed to remove memlock rlimit: %v. Consider using sudo or give necessary capabilities to the program", err))
	}

	// Initialize Prometheus metrics (register the metrics)
	monitoring.InitPrometheus()

	// Start the HTTP server for Prometheus to scrape metrics
	go func() {
		http.Handle("/metrics", promhttp.Handler())
		log.Info("Serving Prometheus metrics on :2112/metrics")
		if err := http.ListenAndServe(":2112", nil); err != nil {
			log.Error(fmt.Sprintf("Error starting Prometheus metrics server: %v", err))
		}
	}()

	nettrack.NetworkTrack(ctx)
}
