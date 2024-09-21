package utils

import (
	"fmt"
	"os/user"
	"strconv"
)

// Function to convert UID to username
func GetUsername(uid uint32) string {
	usr, err := user.LookupId(strconv.Itoa(int(uid)))
	if err != nil {
		return fmt.Sprintf("Unknown UID: %v", uid)
	}
	return usr.Username
}
