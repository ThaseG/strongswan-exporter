package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	version   = "dev"
	buildDate = "unknown"

	listenAddress = flag.String("web.listen-address", ":9234", "Address to listen on for web interface and telemetry")
	metricsPath   = flag.String("web.telemetry-path", "/metrics", "Path under which to expose metrics")
	configFile    = flag.String("config.file", "exporter.yaml", "Path to configuration file")
)

func main() {
	flag.Parse()

	log.Printf("Starting StrongSwan Exporter version %s (built %s)", version, buildDate)

	config, err := loadConfig(*configFile)
	if err != nil {
		log.Fatalf("Error loading config: %v", err)
	}

	collector := NewStrongSwanCollector(config)
	prometheus.MustRegister(collector)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
	<title>StrongSwan Exporter</title>
	<style>
		body { font-family: Arial, sans-serif; margin: 40px; }
		h1 { color: #333; }
		.info { background: #f0f0f0; padding: 20px; border-radius: 5px; margin: 20px 0; }
		a { color: #0066cc; text-decoration: none; }
		a:hover { text-decoration: underline; }
	</style>
</head>
<body>
	<h1>StrongSwan Exporter</h1>
	<div class="info">
		<p><strong>Version:</strong> %s</p>
		<p><strong>Build Date:</strong> %s</p>
	</div>
	<h2>Endpoints</h2>
	<ul>
		<li><a href="%s">Metrics</a> - Prometheus metrics endpoint</li>
		<li><a href="/sessions">Sessions</a> - JSON API with connection details</li>
		<li><a href="/sessions_local">Local Sessions</a> - JSON API with local connection details</li>
		<li><a href="/static">Static Page</a> - HTML view of connections</li>
	</ul>
</body>
</html>`, version, buildDate, *metricsPath)
	})

	http.Handle(*metricsPath, promhttp.Handler())

	http.HandleFunc("/sessions", func(w http.ResponseWriter, r *http.Request) {
		sessions, err := getSessionsJSON(config)
		if err != nil {
			log.Printf("Error getting sessions: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(sessions)
	})

	http.HandleFunc("/sessions_local", func(w http.ResponseWriter, r *http.Request) {
		sessions, err := getSessionsJSON(config)
		if err != nil {
			log.Printf("Error getting sessions: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(sessions)
	})

	http.HandleFunc("/static", func(w http.ResponseWriter, r *http.Request) {
		staticHTML, err := getStaticHTML(config)
		if err != nil {
			http.Error(w, fmt.Sprintf("Error generating static page: %v", err), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(staticHTML))
	})

	log.Printf("Listening on %s", *listenAddress)
	if err := http.ListenAndServe(*listenAddress, nil); err != nil {
		log.Fatalf("Error starting HTTP server: %v", err)
	}
}