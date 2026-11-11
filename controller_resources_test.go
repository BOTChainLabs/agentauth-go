package agentauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestControllerBindingAndSessionFlow(t *testing.T) {
	var keys []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Controller-Key") != "controller-secret" {
			t.Error("missing Controller credential")
		}
		if r.Method != http.MethodGet {
			keys = append(keys, r.Header.Get("Idempotency-Key"))
			if keys[len(keys)-1] == "" {
				t.Error("missing operation key")
			}
		}
		switch r.URL.Path {
		case "/prefix/v1/agents/aag_test/resource-binding-challenges":
			w.WriteHeader(201)
			fmt.Fprint(w, `{"challenge_token":"challenge","challenge_id":"ch_1","message":"sign exactly this","challenge_expires_at":"2026-11-10T10:00:00Z"}`)
		case "/prefix/v1/agents/aag_test/resource-bindings":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			if body["eoa_signature"] != "signature" || body["resource_control_assertion"] != nil {
				t.Error("wrong resource proof")
			}
			w.WriteHeader(201)
			fmt.Fprint(w, `{"resource_binding_id":"arb_test","auth_agent_id":"aag_test","project_id":"project-a","status":"ACTIVE"}`)
		case "/prefix/v1/agents/aag_test/sessions":
			w.WriteHeader(201)
			fmt.Fprint(w, `{"session_id":"ses_test","auth_agent_id":"aag_test","resource_binding_id":"arb_test","status":"DRAFT","policy_digest":"digest"}`)
		case "/prefix/v1/sessions/ses_test:activate":
			var body struct {
				Digest string `json:"policy_digest"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body.Digest != "digest" {
				t.Error("approved digest mismatch")
			}
			fmt.Fprint(w, `{"session_id":"ses_test","status":"ACTIVE","updated_at":"2026-11-10T10:00:00Z"}`)
		case "/prefix/v1/sessions/ses_test/integration-status":
			if r.Header.Get("Idempotency-Key") != "" {
				t.Error("GET has operation key")
			}
			fmt.Fprint(w, `{"session_id":"ses_test","auth_project_id":"project-a","status":"PENDING","checked_at":"2026-11-10T10:00:00Z","components":[]}`)
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	client, err := NewControllerClient(ControllerConfig{BaseURL: server.URL + "/prefix", ControllerKey: "controller-secret", ProjectID: "project-a"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	resource := ResourceSpec{ResourceType: "EOA_ACCOUNT", Network: "eip155:968", Payer: "0x1111111111111111111111111111111111111111", Asset: "0x2222222222222222222222222222222222222222"}
	grant := Grant{ActionType: "X402_PAYMENT", Services: []ServiceRule{{ServiceID: "svc", ConfigVersion: 1}}}
	limits := Limits{PerActionLimit: "1", DailyLimit: "10", LifetimeLimit: "100", MaxInflightUnits: "10", MaxInflightCount: 1}
	challenge, err := client.CreateBindingChallenge(ctx, "aag_test", BindingChallengeRequest{Resource: resource, Grant: grant, GrantLimits: limits, ValidUntil: time.Now().Add(time.Hour), IdempotencyKey: "challenge-op"})
	if err != nil || challenge.Message != "sign exactly this" {
		t.Fatalf("challenge: %+v %v", challenge, err)
	}
	binding, err := client.CreateBinding(ctx, "aag_test", CreateBindingRequest{ChallengeToken: challenge.ChallengeToken, Resource: resource, Grant: grant, GrantLimits: limits, EOASignature: "signature", IdempotencyKey: "binding-op"})
	if err != nil || binding.ResourceBindingID != "arb_test" {
		t.Fatalf("binding: %+v %v", binding, err)
	}
	session, err := client.CreateSession(ctx, "aag_test", CreateSessionRequest{ResourceBindingID: binding.ResourceBindingID, RuntimeCredential: RuntimeCredential{Algorithm: "Ed25519", PublicKey: base64.RawURLEncoding.EncodeToString(make([]byte, 32))}, Rules: grant, Limits: limits, ValidUntil: time.Now().Add(time.Hour), IdempotencyKey: "session-op"})
	if err != nil || session.Status != "DRAFT" {
		t.Fatalf("session: %+v %v", session, err)
	}
	status, err := client.ActivateSession(ctx, session.SessionID, session.PolicyDigest, "activate-op")
	if err != nil || status.Status != "ACTIVE" {
		t.Fatalf("activation: %+v %v", status, err)
	}
	snapshot, err := client.GetIntegrationStatus(ctx, session.SessionID)
	if err != nil || snapshot.Status != "PENDING" {
		t.Fatalf("snapshot: %+v %v", snapshot, err)
	}
	if strings.Join(keys, ",") != "challenge-op,binding-op,session-op,activate-op" {
		t.Fatalf("keys = %v", keys)
	}
}

func TestControllerRejectsWrongProjectBinding(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"resource_binding_id":"arb_test","auth_agent_id":"aag_test","project_id":"other"}`)
	}))
	defer server.Close()
	client, _ := NewControllerClient(ControllerConfig{BaseURL: server.URL, ControllerKey: "secret", ProjectID: "project-a"})
	if _, err := client.GetBinding(context.Background(), "arb_test"); err == nil {
		t.Fatal("accepted wrong Project")
	}
}
