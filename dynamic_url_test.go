package cloudns

import (
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
)

type dynamicURLTestTransport func(*http.Request) (*http.Response, error)

func (f dynamicURLTestTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestDynamicURLDoesNotPrintResponse(t *testing.T) {
	const fakeURL = "https://example.invalid/dynamic/FIXTURE_SECRET"
	oldTransport := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = oldTransport })
	http.DefaultTransport = dynamicURLTestTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/dns/get-dynamic-url.json" && r.URL.Path != "/dns/change-dynamic-url.json" {
			t.Fatalf("unexpected endpoint %s", r.URL.Path)
		}
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"url":"` + fakeURL + `"}`)), Request: r}, nil
	})
	for _, endpoint := range []string{"read", "change"} {
		t.Run(endpoint, func(t *testing.T) {
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			defer w.Close()
			oldStdout := os.Stdout
			os.Stdout = w
			defer func() { os.Stdout = oldStdout }()
			d := DynamicUrl{Domain: "example.test", RecordId: "123"}
			a := &Apiaccess{Authid: 1, Authpassword: "dummy"}
			var response DynamicUrlResponse
			if endpoint == "read" {
				response, err = d.ReadOrCreate(a)
			} else {
				response, err = d.Change(a)
			}
			w.Close()
			os.Stdout = oldStdout
			output, readErr := io.ReadAll(r)
			if err != nil || readErr != nil {
				t.Fatalf("request: %v; capture: %v", err, readErr)
			}
			if response.Url != fakeURL || response.Domain != d.Domain || response.RecordId != d.RecordId {
				t.Fatal("incorrect dynamic URL response")
			}
			if len(output) != 0 {
				t.Fatal("dynamic URL request wrote to stdout")
			}
		})
	}
}
