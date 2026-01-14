package main

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/strongswan/govici/vici"
)

type Session struct {
	Server      string `json:"server"`
	Protocol    string `json:"protocol"`
	UniqueID    string `json:"uniqueid"`
	State       string `json:"state"`
	RemoteHost  string `json:"remotehost"`
	RemotePort  string `json:"remoteport"`
	RemoteID    string `json:"remoteid"`
	RemoteTS    string `json:"remotets"`
	LocalTS     string `json:"localts"`
	Established string `json:"established"`
	BytesIn     string `json:"bytesin"`
	BytesOut    string `json:"bytesout"`
	PacketsIn   string `json:"packetsin"`
	PacketsOut  string `json:"packetsout"`
}

func getSessionsJSON(config *Config) ([]byte, error) {
	sessions, err := getSessions(config)
	if err != nil {
		sessions = []Session{}
	}

	return json.Marshal(sessions)
}

func getSessions(config *Config) ([]Session, error) {
	session, err := vici.NewSession()
	if err != nil {
		return []Session{}, fmt.Errorf("error connecting to StrongSwan: %w", err)
	}
	defer session.Close()

	var sessions []Session

	hostname := "strongswan-server"

	sasMsg, err := session.StreamedCommandRequest("list-sas", "list-sa", nil)
	if err != nil {
		return []Session{}, fmt.Errorf("error listing SAs: %w", err)
	}

	messages := sasMsg.Messages()
	
	for _, msg := range messages {
		for _, saName := range msg.Keys() {
			saData, ok := msg.Get(saName).(map[string]interface{})
			if !ok {
				continue
			}

			uniqueID := saName
			state := "UNKNOWN"
			if st, ok := saData["state"].(string); ok {
				state = st
			}

			remoteHost := ""
			remotePort := ""
			if remoteHostFull, ok := saData["remote-host"].(string); ok {
				remoteHost = remoteHostFull
				if idx := len(remoteHostFull) - 1; idx > 0 {
					for i := len(remoteHostFull) - 1; i >= 0; i-- {
						if remoteHostFull[i] == ':' {
							remoteHost = remoteHostFull[:i]
							remotePort = remoteHostFull[i+1:]
							break
						}
					}
				}
			}

			remoteID := ""
			if rid, ok := saData["remote-id"].(string); ok {
				remoteID = rid
			}

			established := ""
			if estTime, ok := saData["established"].(string); ok {
				if ts, err := parseTimestamp(estTime); err == nil {
					established = ts.Format("2006-01-02 15:04:05")
				}
			}

			protocol := "ikev2"
			if version, ok := saData["version"].(string); ok {
				protocol = version
			}

			if childSAs, ok := saData["child-sas"].(map[string]interface{}); ok {
				for _, childData := range childSAs {
					if child, ok := childData.(map[string]interface{}); ok {
						sess := Session{
							Server:      hostname,
							Protocol:    protocol,
							UniqueID:    uniqueID,
							State:       state,
							RemoteHost:  remoteHost,
							RemotePort:  remotePort,
							RemoteID:    remoteID,
							Established: established,
						}

						if remoteTSData, ok := child["remote-ts"].([]interface{}); ok && len(remoteTSData) > 0 {
							if ts, ok := remoteTSData[0].(string); ok {
								sess.RemoteTS = ts
							}
						}

						if localTSData, ok := child["local-ts"].([]interface{}); ok && len(localTSData) > 0 {
							if ts, ok := localTSData[0].(string); ok {
								sess.LocalTS = ts
							}
						}

						if bytesIn, ok := child["bytes-in"].(string); ok {
							sess.BytesIn = bytesIn
						}
						if bytesOut, ok := child["bytes-out"].(string); ok {
							sess.BytesOut = bytesOut
						}
						if packetsIn, ok := child["packets-in"].(string); ok {
							sess.PacketsIn = packetsIn
						}
						if packetsOut, ok := child["packets-out"].(string); ok {
							sess.PacketsOut = packetsOut
						}

						sessions = append(sessions, sess)
					}
				}
			}
		}
	}

	return sessions, nil
}

func parseTimestamp(ts string) (time.Time, error) {
	var unixTS int64
	_, err := fmt.Sscanf(ts, "%d", &unixTS)
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(unixTS, 0), nil
}