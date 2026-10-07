package main

import (
	"strconv"
	"sync"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
)

type StrongSwanCollector struct {
	conf   *Config
	logger log.Logger

	// Background refresh cache
	mu          sync.RWMutex
	cachedState *collectedState
}

// collectedState holds the last collected snapshot
type collectedState struct {
	sessions []SessionExport
	ikeSAs   int
	product  string
	version  string // used for probe_success label
	success  float64
}

var (
	swanInfo          = prometheus.NewDesc("strongswan_info", "Software info", []string{"product", "version"}, nil)
	swanSessTotal     = prometheus.NewDesc("strongswan_sessions_total", "Total number of active sessions", nil, nil)
	swanBytesInTotal  = prometheus.NewDesc("strongswan_bytes_in_total", "Total number of bytes received", []string{"client"}, nil)
	swanBytesOutTotal = prometheus.NewDesc("strongswan_bytes_out_total", "Total number of bytes sent", []string{"client"}, nil)
	swanProbeSuccess  = prometheus.NewDesc("probe_success", "StrongSwan Status", []string{"version"}, nil)
)

// Implement prometheus.Collector Describe method
func (c *StrongSwanCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- swanProbeSuccess
	ch <- swanInfo
	ch <- swanSessTotal
	ch <- swanBytesInTotal
	ch <- swanBytesOutTotal
}

// Implement prometheus.Collector Collect method — serves from cache
func (c *StrongSwanCollector) Collect(ch chan<- prometheus.Metric) {
	c.mu.RLock()
	state := c.cachedState
	c.mu.RUnlock()

	if state == nil || state.success == 0 {
		// No data yet or charon unreachable — emit a failing probe and zeros
		ch <- prometheus.MustNewConstMetric(swanProbeSuccess, prometheus.GaugeValue, 0, "")
		ch <- prometheus.MustNewConstMetric(swanSessTotal, prometheus.GaugeValue, 0)
		return
	}

	ch <- prometheus.MustNewConstMetric(swanProbeSuccess, prometheus.GaugeValue, state.success, state.version)
	ch <- prometheus.MustNewConstMetric(swanInfo, prometheus.CounterValue, 1, state.product, state.version)
	ch <- prometheus.MustNewConstMetric(swanSessTotal, prometheus.GaugeValue, float64(state.ikeSAs))

	// Label uniquely identifies each session:
	// remote identity + remote traffic selector (virtual IP) + protocol.
	// During a rekey two Child SAs briefly share the same selector, so the
	// counters are summed per label to avoid duplicate series.
	bytesIn := make(map[string]float64)
	bytesOut := make(map[string]float64)
	var order []string
	for _, v := range state.sessions {
		clientLabel := v.RemoteID + "_" + v.RemoteTs + "_" + v.Protocol
		if _, ok := bytesIn[clientLabel]; !ok {
			order = append(order, clientLabel)
			bytesIn[clientLabel] = 0
			bytesOut[clientLabel] = 0
		}
		if bi, err := strconv.ParseFloat(v.BytesIn, 64); err == nil {
			bytesIn[clientLabel] += bi
		}
		if bo, err := strconv.ParseFloat(v.BytesOut, 64); err == nil {
			bytesOut[clientLabel] += bo
		}
	}

	for _, clientLabel := range order {
		ch <- prometheus.MustNewConstMetric(swanBytesInTotal, prometheus.CounterValue, bytesIn[clientLabel], clientLabel)
		ch <- prometheus.MustNewConstMetric(swanBytesOutTotal, prometheus.CounterValue, bytesOut[clientLabel], clientLabel)
	}
}

// StartBackgroundRefresh launches the collection ticker at the configured interval.
// Interval is read from refresh_interval in exporter.yaml (seconds); defaults to 15.
// Call this once after creating the collector (before registering with Prometheus).
func (c *StrongSwanCollector) StartBackgroundRefresh() {
	interval := c.conf.RefreshInterval
	if interval <= 0 {
		interval = 15
	}

	_ = level.Info(c.logger).Log("msg", "Starting background refresh", "interval_seconds", interval)

	// Collect immediately on start so the first scrape is never empty
	c.collect()

	go func() {
		ticker := time.NewTicker(time.Duration(interval) * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			c.collect()
		}
	}()
}

// collect does the actual work and stores the result in the cache
func (c *StrongSwanCollector) collect() {
	c.debugLog("task", "Collecting StrongSwan metrics", "target", c.conf.ViciSocket)

	newState := &collectedState{}

	state, err := getStrongSwanState(c.conf)
	if err != nil {
		_ = level.Error(c.logger).Log("task", "Collecting StrongSwan metrics", "status", "ERROR", "msg", err)
	}
	// state is non-nil when charon answered the version request, even if
	// listing SAs failed afterwards
	if state != nil {
		newState.product = state.product
		newState.version = state.version
		newState.success = 1
		if err == nil {
			newState.sessions = state.sessions
			newState.ikeSAs = state.ikeSAs
		}
	}

	c.debugLog("task", "Collection complete", "ike_sas", newState.ikeSAs, "child_sas", len(newState.sessions), "version", newState.version)

	c.mu.Lock()
	c.cachedState = newState
	c.mu.Unlock()
}

// debugLog emits a debug-level log only when debug is enabled in config
func (c *StrongSwanCollector) debugLog(keyvals ...interface{}) {
	if c.conf.Debug {
		_ = level.Debug(c.logger).Log(keyvals...)
	}
}
