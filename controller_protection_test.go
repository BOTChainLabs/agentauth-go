package agentauth

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

type protectionTransport func(*http.Request) (*http.Response, error)

func (f protectionTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestEnableProtectionUsesControllerAndStableKey(t *testing.T) {
	calls := 0
	client, err := NewControllerClient(ControllerConfig{BaseURL: "https://auth.example", ControllerKey: "ack_test.secret", ProjectID: "proj_test", HTTPClient: &http.Client{Transport: protectionTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != "POST" || r.URL.Path != "/v1/sessions/ses_test/payment-protection:enable" || r.Header.Get("X-Controller-Key") != "ack_test.secret" || r.Header.Get("Idempotency-Key") != "enable-1" {
			t.Errorf("wrong request: %s %s %v", r.Method, r.URL.Path, r.Header)
		}
		raw, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(raw), `"confirmation_ref":"record-1"`) {
			t.Errorf("missing confirmation: %s", raw)
		}
		return &http.Response{StatusCode: 202, Body: io.NopCloser(strings.NewReader(`{"operation_id":"ape_test","project_id":"proj_test","session_id":"ses_test","status":"PENDING"}`)), Header: make(http.Header)}, nil
	})}})
	if err != nil {
		t.Fatal(err)
	}
	out, err := client.EnablePaymentProtection(context.Background(), "ses_test", strings.Repeat("a", 64), "record-1", "enable-1")
	if err != nil || out.OperationID != "ape_test" || calls != 1 {
		t.Fatalf("operation=%+v err=%v calls=%d", out, err, calls)
	}
}
