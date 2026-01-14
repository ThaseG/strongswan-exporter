package main

import (
	"fmt"
	"log"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/strongswan/govici/vici"
)

type StrongSwanCollector struct {
	config *Config

	up            *prometheus.Desc
	info          *prometheus.Desc
	sessionsTotal *prometheus.Desc
	bytesIn       *prometheus.Desc
	bytesOut      *prometheus.Desc
}

func NewStrongSwanCollector(config *Config) *StrongSwanCollector {
	return &StrongSwanCollector{
		config: config,
		up: prometheus.NewDesc(
			"probe_success",
			"StrongSwan Status",
			[]string{"version"},
			nil,
		),
		info: prometheus.NewDesc(
			"strongswan_info",
			"Software info",
			[]string{"product", "version"},
			nil,
		),
		sessionsTotal: prometheus.NewDesc(
			"strongswan_sessions_total",
			"Total number of active sessions",
			nil,
			nil,
		),
		bytesIn: prometheus.NewDesc(
			"strongswan_bytes_in_total",
			"Total number of bytes received",
			[]string{"client"},
			nil,
		),
		bytesOut: prometheus.NewDesc(
			"strongswan_bytes_out_total",
			"Total number of bytes sent",
			[]string{"client"},
			nil,
		),
	}
}

func (c *StrongSwanCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.up
	ch <- c.info
	ch <- c.sessionsTotal
	ch <- c.bytesIn
	ch <- c.bytesOut
}

func (c *StrongSwanCollector) Collect(ch chan<- prometheus.Metric) {
	session, err := vici.NewSession()
	if err != nil {
		log.Printf("Error connecting to StrongSwan VICI socket: %v", err)
		ch <- prometheus.MustNewConstMetric(c.up, prometheus.GaugeValue, 0, "")
		ch <- prometheus.MustNewConstMetric(c.sessionsTotal, prometheus.GaugeValue, 0)
		return
	}
	defer session.Close()

	versionMsg, err := session.CommandRequest("version", nil)
	if err != nil {
		log.Printf("Error getting version: %v", err)
		ch <- prometheus.MustNewConstMetric(c.up, prometheus.GaugeValue, 0, "")
		ch <- prometheus.MustNewConstMetric(c.sessionsTotal, prometheus.GaugeValue, 0)
		return
	}

	version := ""
	daemon := "StrongSwan"
	if d, ok := versionMsg.Get("daemon").(string); ok {
		daemon = d
	}
	if ver, ok := versionMsg.Get("version").(string); ok {
		version = ver
	}

	ch <- prometheus.MustNewConstMetric(c.up, prometheus.GaugeValue, 1, version)
	ch <- prometheus.MustNewConstMetric(c.info, prometheus.CounterValue, 1, daemon, version)

	sasMsg, err := session.StreamedCommandRequest("list-sas", "list-sa", nil)
	if err != nil {
		log.Printf("Error listing SAs: %v", err)
		ch <- prometheus.MustNewConstMetric(c.sessionsTotal, prometheus.GaugeValue, 0)
		return
	}

	sessionCount := 0
	messages := sasMsg.Messages()
	
	for _, msg := range messages {
		for _, sa := range msg.Keys() {
			sessionCount++

			saData, ok := msg.Get(sa).(map[string]interface{})
			if !ok {
				continue
			}

			clientID := sa
			if remoteID, ok := saData["remote-id"].(string); ok {
				clientID = remoteID
			}

			if childSAs, ok := saData["child-sas"].(map[string]interface{}); ok {
				for _, childData := range childSAs {
					if child, ok := childData.(map[string]interface{}); ok {
						if bytesInStr, ok := child["bytes-in"].(string); ok {
							if bytesIn, err := parseBytes(bytesInStr); err == nil {
								ch <- prometheus.MustNewConstMetric(
									c.bytesIn,
									prometheus.CounterValue,
									float64(bytesIn),
									clientID,
								)
							}
						}

						if bytesOutStr, ok := child["bytes-out"].(string); ok {
							if bytesOut, err := parseBytes(bytesOutStr); err == nil {
								ch <- prometheus.MustNewConstMetric(
									c.bytesOut,
									prometheus.CounterValue,
									float64(bytesOut),
									clientID,
								)
							}
						}
					}
				}
			}
		}
	}

	ch <- prometheus.MustNewConstMetric(c.sessionsTotal, prometheus.GaugeValue, float64(sessionCount))
}

func parseBytes(s string) (uint64, error) {
	var bytes uint64
	_, err := fmt.Sscanf(s, "%d", &bytes)
	return bytes, err
}