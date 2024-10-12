package core

import (
	"context"

	"github.com/cilium/ebpf/rlimit"
	"github.com/containerscrew/kernelsnoop/internal/dto"
)

// Retrieve context data (log and config) from the context
func GetContextData(ctx context.Context) *dto.ContextData {
	contextData, _ := ctx.Value(dto.ContextDataKey).(*dto.ContextData)
	return contextData
}

// RemoveMemLock removes the memory lock limit for the current process.
func RemoveMemLock() error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return err
	}
	return nil
}
