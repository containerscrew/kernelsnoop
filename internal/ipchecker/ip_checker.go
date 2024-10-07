// Get geo location of an IP address using custom API https://github.com/containerscrew/iproxy
package ipchecker

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
)

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

// Get ip info from custom API
func GetIPInfo(ip string) (GeoLocation, error) {
	url := fmt.Sprintf("http://iproxy:8000/api/v1/%s", ip)
	resp, err := http.Get(url)
	if err != nil {
		return GeoLocation{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return GeoLocation{}, fmt.Errorf("API request failed with status: %s", resp.Status)
	}

	var info GeoLocation
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return GeoLocation{}, err
	}

	return info, nil
}

func PrivateIPCheck(ip string) bool {
    ipAddress := net.ParseIP(ip)
    return ipAddress.IsPrivate()
}
