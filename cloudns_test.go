package cloudns

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestNewActivateFailover(t *testing.T) {
	cases := []struct {
		name         string
		settings     CheckSettings
		checkType    string
		wantSettings map[string]interface{}
	}{
		{
			name:         "Ping check",
			checkType:    "1",
			settings:     CheckSettings{Timeout: "3", LatencyLimit: "5"},
			wantSettings: map[string]interface{}{"timeout": "3", "latency_limit": "5"},
		},
		{
			name:         "HTTP check",
			checkType:    "4",
			settings:     CheckSettings{Host: "example.test", Port: 443, Path: "somepath", HttpRequestType: "GET"},
			wantSettings: map[string]interface{}{"host": "example.test", "port": float64(443), "path": "somepath", "http_request_type": "GET"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			credentials := &Apiaccess{Authid: 1, Authpassword: "dummy"}
			failover := Failover{
				Domain: "example.test", RecordId: "123", FailoverType: tc.checkType,
				MainIP: "192.0.2.1", BackupIp1: "192.0.2.2",
				UpEventHandler: "2", DownEventHandler: "2",
				NotificationMail: "alerts@example.test", CheckSettings: tc.settings,
			}
			want := map[string]interface{}{
				"auth-id": float64(1), "auth-password": "dummy", "id": "",
				"domain-name": "example.test", "record-id": "123", "check_type": tc.checkType,
				"main_ip": "192.0.2.1", "backup_ip_1": "192.0.2.2",
				"up_event_handler": "2", "down_event_handler": "2",
				"notification_mail": "alerts@example.test",
			}
			for key, value := range tc.wantSettings {
				want[key] = value
			}

			// Construct and serialize the request without invoking Create(),
			// which would send a request to the live ClouDNS API.
			request := newActivateFailover(failover, credentials)
			payload, err := json.Marshal(request)
			if err != nil {
				t.Fatalf("marshal request: %v", err)
			}
			var body map[string]interface{}
			if err := json.Unmarshal(payload, &body); err != nil {
				t.Fatalf("decode request: %v", err)
			}
			if !reflect.DeepEqual(body, want) {
				t.Errorf("request body = %#v, want %#v", body, want)
			}
		})
	}
}
