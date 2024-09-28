package utils

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os/user"
	"strconv"
)

// Function to convert IP to uint32
func IntToIP(ipNum uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, ipNum)
	return ip
}

// Function to convert UID to username
func GetUsername(uid uint32) string {
	usr, err := user.LookupId(strconv.Itoa(int(uid)))
	if err != nil {
		return fmt.Sprintf("Unknown UID: %v", uid)
	}
	return usr.Username
}

// IpResolver return the FQDN of an IP address
func IpLookup(ip string) (string, error) {
	fqdn, err := net.LookupAddr(ip)
	if err != nil {
		return "Unknown", err
	}
	if len(fqdn) > 0 {
		return fqdn[0], nil // just return the first entry
	}
	return "Unknown", nil
}

// Structure to hold the IP information
type IPInfo struct {
	Status  string `json:"status"`
	AS      string `json:"as"`
	Query   string `json:"query"`
	Country string `json:"country"`
	Region  string `json:"region"`
	City    string `json:"city"`
}

// GetIpINfo returns the "as" field from the ip-api.com API.
func GetIPInfo(ip string) (IPInfo, error) {
	url := fmt.Sprintf("http://ip-api.com/json/%s", ip)
	resp, err := http.Get(url)
	if err != nil {
		return IPInfo{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return IPInfo{}, fmt.Errorf("API request failed with status: %s", resp.Status)
	}

	var info IPInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return IPInfo{}, err
	}

	// Check if the API returned a success status
	if info.Status != "success" {
		return IPInfo{}, fmt.Errorf("failed to get info for IP: %s", ip)
	}

	return info, nil
}
