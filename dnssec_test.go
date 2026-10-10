package cloudns

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

type dnssecTransport func(*http.Request) (*http.Response, error)

func (f dnssecTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func mockDNSSEC(t *testing.T, path, response string, code int, sub bool, status *int) {
	t.Helper()
	old := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = old })
	http.DefaultTransport = dnssecTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/dns/"+path+".json" || r.Method != "POST" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL)
		}
		var b map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
			t.Fatal(err)
		}
		if b["domain-name"] != "example.test" || b["auth-password"] != "dummy" {
			t.Errorf("bad payload %#v", b)
		}
		auth, other := "auth-id", "sub-auth-id"
		if sub {
			auth, other = other, auth
		}
		if b[auth] != float64(42) {
			t.Errorf("bad auth %#v", b)
		}
		if _, ok := b[other]; ok {
			t.Errorf("unexpected %s", other)
		}
		if status != nil {
			if b["status"] != float64(*status) {
				t.Errorf("bad status %#v", b)
			}
		} else if _, ok := b["status"]; ok {
			t.Error("unexpected status")
		}
		return &http.Response{StatusCode: code, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(response)), Request: r}, nil
	})
}
func TestDNSSECOperations(t *testing.T) {
	z := Zone{Domain: "example.test"}
	ctx := context.Background()
	zero, one := 0, 1
	for _, sub := range []bool{false, true} {
		a := &Apiaccess{Authid: 42, Authpassword: "dummy"}
		if sub {
			a.Authid = 0
			a.Subauthid = 42
		}
		for _, tc := range []struct {
			path   string
			status *int
			call   func() error
		}{
			{"activate-dnssec", nil, func() error { return z.ActivateDNSSEC(ctx, a) }},
			{"deactivate-dnssec", nil, func() error { return z.DeactivateDNSSEC(ctx, a) }},
			{"set-dnssec-optout", &zero, func() error { return z.SetDNSSECOptOut(ctx, a, false) }},
			{"set-dnssec-optout", &one, func() error { return z.SetDNSSECOptOut(ctx, a, true) }},
		} {
			t.Run(tc.path, func(t *testing.T) {
				mockDNSSEC(t, tc.path, `{"status":"Success"}`, 200, sub, tc.status)
				if err := tc.call(); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}
func TestDNSSECAvailable(t *testing.T) {
	for _, tc := range []struct {
		body       string
		want, fail bool
	}{{"1", true, false}, {`"0"`, false, false}, {`{"status":"Failed","statusDescription":"denied"}`, false, true}, {"null", false, true}, {"{}", false, true}, {"invalid", false, true}} {
		t.Run(tc.body, func(t *testing.T) {
			mockDNSSEC(t, "is-dnssec-available", tc.body, 200, false, nil)
			got, err := (Zone{Domain: "example.test"}).DNSSECAvailable(context.Background(), &Apiaccess{Authid: 42, Authpassword: "dummy"})
			if got != tc.want || (err != nil) != tc.fail {
				t.Fatalf("got %v, %v", got, err)
			}
		})
	}
}
func TestDNSSECDetails(t *testing.T) {
	for _, tc := range []struct {
		name, body           string
		active, optout, fail bool
	}{
		{"active", `{"status":"1","optout":"1","ds":["example.test. 3600 IN DS 123 13 2 ABCD"],"dnskey":["example.test. 3600 IN DNSKEY 257 3 13 KEY"],"ds_records":[{"key_tag":"123","algorithm":"13","digest_type":"2","digest":"ABCD"}]}`, true, true, false},
		{"inactive", `{"status":"Failed","statusDescription":"dnssec_not_active"}`, false, false, false},
		{"auth", `{"status":"Failed","statusDescription":"Invalid authentication"}`, false, false, true},
		{"missing", `{"status":"Failed","statusDescription":"Missing domain-name"}`, false, false, true},
		{"malformed", "{}", false, false, true},
		{"bad optout", `{"status":1,"optout":2}`, false, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mockDNSSEC(t, "get-dnssec-ds-records", tc.body, 200, false, nil)
			got, err := (Zone{Domain: "example.test"}).DNSSEC(context.Background(), &Apiaccess{Authid: 42, Authpassword: "dummy"})
			if (err != nil) != tc.fail {
				t.Fatalf("err=%v", err)
			}
			if err != nil {
				return
			}
			if got.Enabled != tc.active || got.OptOut != tc.optout {
				t.Fatalf("got %#v", got)
			}
			if tc.active && (len(got.DS) != 1 || len(got.DNSKEY) != 1 || got.DSRecords[0].KeyTag != "123") {
				t.Fatalf("records %#v", got)
			}
		})
	}
}
func TestDNSSECErrors(t *testing.T) {
	for _, tc := range []struct {
		body string
		code int
	}{{`{"status":"Failed","statusDescription":"denied"}`, 200}, {"{}", 200}, {"not json", 200}, {`{"status":"Success"}`, 500}} {
		t.Run(tc.body, func(t *testing.T) {
			mockDNSSEC(t, "activate-dnssec", tc.body, tc.code, false, nil)
			if err := (Zone{Domain: "example.test"}).ActivateDNSSEC(context.Background(), &Apiaccess{Authid: 42, Authpassword: "dummy"}); err == nil {
				t.Fatal("expected error")
			}
		})
	}
	if err := (Zone{}).ActivateDNSSEC(context.Background(), &Apiaccess{}); err == nil {
		t.Fatal("empty domain")
	}
	if err := (Zone{Domain: "example.test"}).ActivateDNSSEC(context.Background(), nil); err == nil {
		t.Fatal("nil auth")
	}
}
