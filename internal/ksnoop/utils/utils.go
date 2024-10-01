package utils

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/user"
	"reflect"
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

// Struct to hold the IP information from ip.guide
type IPInfo struct {
	IP      string   `json:"ip"`
	Network Network  `json:"network"`
	Location Location `json:"location"`
}

type Network struct {
	CIDR             string          `json:"cidr"`
	Hosts            Hosts           `json:"hosts"`
	AutonomousSystem AutonomousSystem `json:"autonomous_system"`
}

type Hosts struct {
	Start string `json:"start"`
	End   string `json:"end"`
}

type AutonomousSystem struct {
	ASN          int    `json:"asn"`
	Name         string `json:"name"`
	Organization string `json:"organization"`
	Country      string `json:"country"`
	RIR          string `json:"rir"`
}

type Location struct {
	City      string  `json:"city"`
	Country   string  `json:"country"`
	Timezone  string  `json:"timezone"`
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
}

// Sometimes the location field is empty
var defaultLocation = Location{
	City:      "Unknown",
	Country:   "Unknown",
	Timezone:  "UTC",
	Latitude:  0.0,
	Longitude: 0.0,
}

// GetIpINfo returns the "as" field from the ip-api.com API.
func GetIPInfo(ip string) (IPInfo, error) {
	url := fmt.Sprintf("https://ip.guide/%s", ip)
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

	// If location is empty
	if reflect.DeepEqual(info.Location, Location{}) {
		info.Location = defaultLocation
	}

	// Check if the API returned a success status
	return info, nil
}


// virustotal check for the IP address
// VirusTotalResponse represents the response from the VirusTotal API
type VirusTotalResponse struct {
	Data struct {
		Attributes struct {
			LastAnalysisStats struct {
				Harmless   int `json:"harmless"`
				Malicious  int `json:"malicious"`
				Suspicious int `json:"suspicious"`
				Undetected int `json:"undetected"`
				Timeout    int `json:"timeout"`
			} `json:"last_analysis_stats"`
		} `json:"attributes"`
	} `json:"data"`
}

// GetVirusTotalInfo retrieves information about an IP address from VirusTotal
func GetVirusTotalInfo(ip string) (VirusTotalResponse, error) {
	apiKey := os.Getenv("VIRUSTOTAL_API_KEY")
	if apiKey == "" {
		return VirusTotalResponse{}, fmt.Errorf("VIRUSTOTAL_API_KEY environment variable not set")
	}

	url := fmt.Sprintf("https://www.virustotal.com/api/v3/ip_addresses/%s", ip)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return VirusTotalResponse{}, err
	}

	req.Header.Set("accept", "application/json")
	req.Header.Set("x-apikey", apiKey)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return VirusTotalResponse{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return VirusTotalResponse{}, fmt.Errorf("API request failed with status: %s", resp.Status)
	}

	var vtResponse VirusTotalResponse
	if err := json.NewDecoder(resp.Body).Decode(&vtResponse); err != nil {
		return VirusTotalResponse{}, err
	}

	return vtResponse, nil
}
