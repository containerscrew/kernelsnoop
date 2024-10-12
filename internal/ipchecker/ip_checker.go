package ipchecker

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"
)

// GeoLocation represents the response structure for the IP info API
type GeoLocation struct {
	Status      string  `json:"status"`
	City        string  `json:"city"`
	CountryCode string  `json:"countryCode"`
	RegionName  string  `json:"regionName"`
	Region      string  `json:"region"`
	Country     string  `json:"country"`
	Zip         string  `json:"zip"`
	Lat         float64 `json:"lat"`
	Lon         float64 `json:"lon"`
	Timezone    string  `json:"timezone"`
	Isp         string  `json:"isp"`
	Org         string  `json:"org"`
	As          string  `json:"as"`
	Query       string  `json:"query"`
}

// GetIPInfo retrieves geo-location information for a given IP address from a custom API
func GetIPInfo(ip string) (GeoLocation, error) {
	url := fmt.Sprintf("http://iproxy:8000/api/v1/%s", ip)

	// Create a custom HTTP client with a timeout
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	// Perform the GET request
	resp, err := client.Get(url)
	if err != nil {
		return GeoLocation{}, fmt.Errorf("failed to make request: %v", err)
	}
	defer resp.Body.Close()

	// Check for non-OK status
	if resp.StatusCode != http.StatusOK {
		return GeoLocation{}, fmt.Errorf("API request failed with status: %s", resp.Status)
	}

	// Parse the response body into the GeoLocation struct
	var info GeoLocation
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return GeoLocation{}, fmt.Errorf("failed to decode response: %v", err)
	}

	return info, nil
}

// PrivateIPCheck checks if the given IP is private (non-routable)
func PrivateIPCheck(ip string) bool {
	ipAddress := net.ParseIP(ip)
	if ipAddress == nil {
		return false // Invalid IP
	}
	return ipAddress.IsPrivate()
}
