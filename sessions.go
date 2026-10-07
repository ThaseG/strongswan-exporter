package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/strongswan/govici/vici"
)

// SessionExport is one Child SA (tunnel) of an IKE SA. Field names follow
// the OpenVPN exporter: p1 = IKE SA (phase 1), p2 = Child SA (phase 2).
type SessionExport struct {
	Server      string `json:"server"`
	Protocol    string `json:"protocol"`
	P1Uniqueid  string `json:"p1uniqueid"`
	P2Uniqueid  string `json:"p2uniqueid"`
	State       string `json:"state"`
	RemoteHost  string `json:"remotehost"`
	RemotePort  string `json:"remoteport"`
	RemoteID    string `json:"remoteid"`
	RemoteTs    string `json:"remotets"`
	LocalTs     string `json:"localts"`
	Established string `json:"established"`
	BytesIn     string `json:"bytesin"`
	BytesOut    string `json:"bytesout"`
	PacketsIn   string `json:"packetsin"`
	PacketsOut  string `json:"packetsout"`
}

// ikeSA mirrors the list-sa event layout described in the VICI README
type ikeSA struct {
	UniqueID      string             `vici:"uniqueid"`
	Version       string             `vici:"version"`
	State         string             `vici:"state"`
	RemoteHost    string             `vici:"remote-host"`
	RemotePort    string             `vici:"remote-port"`
	RemoteID      string             `vici:"remote-id"`
	RemoteXauthID string             `vici:"remote-xauth-id"`
	RemoteEapID   string             `vici:"remote-eap-id"`
	Established   string             `vici:"established"` // seconds since establishment
	ChildSAs      map[string]childSA `vici:"child-sas"`
}

type childSA struct {
	UniqueID   string   `vici:"uniqueid"`
	State      string   `vici:"state"`
	BytesIn    string   `vici:"bytes-in"`
	BytesOut   string   `vici:"bytes-out"`
	PacketsIn  string   `vici:"packets-in"`
	PacketsOut string   `vici:"packets-out"`
	LocalTs    []string `vici:"local-ts"`
	RemoteTs   []string `vici:"remote-ts"`
}

// strongSwanState is a single snapshot read from the VICI socket
type strongSwanState struct {
	sessions []SessionExport
	ikeSAs   int
	product  string
	version  string
}

func sessionsHandler(w http.ResponseWriter, r *http.Request, conf *Config, logger log.Logger) {
	state, err := getStrongSwanState(conf)
	if err != nil {
		_ = level.Warn(logger).Log("task", "sessions handler", "msg", err.Error())
		state = &strongSwanState{}
	}

	sessions := state.sessions
	if sessions == nil {
		sessions = []SessionExport{}
	}

	jsondata, err := json.Marshal(sessions)
	if err != nil {
		w.WriteHeader(500)
		fmt.Fprint(w, err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_, err = w.Write(jsondata)
	if err != nil {
		_ = level.Error(logger).Log("task", "HTTP", "write", err.Error())
	}
}

// getStrongSwanState queries charon over VICI for its version and all SAs
func getStrongSwanState(conf *Config) (*strongSwanState, error) {
	session, err := vici.NewSession(vici.WithSocketPath(conf.ViciSocket))
	if err != nil {
		return nil, fmt.Errorf("error connecting to StrongSwan VICI socket %s: %w", conf.ViciSocket, err)
	}
	defer func() { _ = session.Close() }()

	versionMsg, err := session.CommandRequest("version", nil)
	if err != nil {
		return nil, fmt.Errorf("error getting version: %w", err)
	}

	state := &strongSwanState{product: "charon"}
	if d, ok := versionMsg.Get("daemon").(string); ok {
		state.product = d
	}
	if v, ok := versionMsg.Get("version").(string); ok {
		state.version = v
	}

	stream, err := session.StreamedCommandRequest("list-sas", "list-sa", nil)
	if err != nil {
		return state, fmt.Errorf("error listing SAs: %w", err)
	}

	for _, msg := range stream.Messages() {
		if err := msg.Err(); err != nil {
			return state, fmt.Errorf("error listing SAs: %w", err)
		}

		// Each list-sa event holds one IKE SA keyed by its connection name
		for _, name := range msg.Keys() {
			section, ok := msg.Get(name).(*vici.Message)
			if !ok {
				continue
			}

			var sa ikeSA
			if err := vici.UnmarshalMessage(section, &sa); err != nil {
				return state, fmt.Errorf("error parsing IKE SA %s: %w", name, err)
			}

			state.ikeSAs++
			state.sessions = append(state.sessions, buildSessions(conf.ServerName, sa)...)
		}
	}

	return state, nil
}

// buildSessions flattens an IKE SA into one SessionExport per Child SA
func buildSessions(server string, sa ikeSA) []SessionExport {
	// Prefer the EAP / XAuth identity, since remote-id is often only an IP
	// address for road-warrior clients authenticating with EAP
	remoteID := sa.RemoteID
	if sa.RemoteXauthID != "" {
		remoteID = sa.RemoteXauthID
	}
	if sa.RemoteEapID != "" {
		remoteID = sa.RemoteEapID
	}

	protocol := "ikev2"
	if sa.Version != "" {
		protocol = "ikev" + sa.Version
	}

	established := ""
	if secs, err := strconv.ParseInt(sa.Established, 10, 64); err == nil {
		established = time.Now().Add(-time.Duration(secs) * time.Second).Format("2006-01-02 15:04:05")
	}

	// Map iteration order is random, keep output stable
	keys := make([]string, 0, len(sa.ChildSAs))
	for k := range sa.ChildSAs {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var sessions []SessionExport
	for _, k := range keys {
		child := sa.ChildSAs[k]
		sessions = append(sessions, SessionExport{
			Server:      server,
			Protocol:    protocol,
			P1Uniqueid:  sa.UniqueID,
			P2Uniqueid:  child.UniqueID,
			State:       sa.State,
			RemoteHost:  sa.RemoteHost,
			RemotePort:  sa.RemotePort,
			RemoteID:    remoteID,
			RemoteTs:    first(child.RemoteTs),
			LocalTs:     first(child.LocalTs),
			Established: established,
			BytesIn:     orZero(child.BytesIn),
			BytesOut:    orZero(child.BytesOut),
			PacketsIn:   orZero(child.PacketsIn),
			PacketsOut:  orZero(child.PacketsOut),
		})
	}

	return sessions
}

func first(list []string) string {
	if len(list) == 0 {
		return ""
	}
	return list[0]
}

func orZero(s string) string {
	if s == "" {
		return "0"
	}
	return s
}
