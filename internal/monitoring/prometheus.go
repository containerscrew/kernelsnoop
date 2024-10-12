package monitoring

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Define the Prometheus metrics for TCP and UDP connections
var (
	TCPConnections = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "tcp_connections_total",
			Help: "Total number of TCP connections.",
		},
		[]string{"src_addr", "dst_addr", "src_port", "dst_port", "comm"},
	)

	UDPConnections = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "udp_connections_total",
			Help: "Total number of UDP connections.",
		},
		[]string{"src_addr", "dst_addr", "src_port", "dst_port", "comm"},
	)
)

// InitPrometheus registers the Prometheus metrics
func InitPrometheus() {
	prometheus.MustRegister(TCPConnections)
	prometheus.MustRegister(UDPConnections)
}

// TrackTCPEvent updates the Prometheus metrics for a TCP event
func TrackTCPEvent(srcAddr, dstAddr, srcPort, dstPort, comm string) {
	TCPConnections.With(prometheus.Labels{
		"src_addr": srcAddr,
		"dst_addr": dstAddr,
		"src_port": srcPort,
		"dst_port": dstPort,
		"comm":     comm,
	}).Inc()
}

// TrackUDPEvent updates the Prometheus metrics for a UDP event
func TrackUDPEvent(srcAddr, dstAddr, srcPort, dstPort, comm string) {
	UDPConnections.With(prometheus.Labels{
		"src_addr": srcAddr,
		"dst_addr": dstAddr,
		"src_port": srcPort,
		"dst_port": dstPort,
		"comm":     comm,
	}).Inc()
}
