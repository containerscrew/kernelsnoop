// 	if err := rlimit.RemoveMemlock(); err != nil {
// 		log.Error(fmt.Sprintf("failed to remove memlock rlimit: %v. Consider using sudo or give necessary capabilities to the program", err))
// 	}

package core

import (
	"context"

	"github.com/cilium/ebpf/rlimit"
)

// RemoveMemLock removes the memory lock limit for the current process.
func RemoveMemLock(ctx context.Context) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return err
	}
	return nil
}
