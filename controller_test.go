package agentauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRegisterAndRecoverAgent(t *testing.T) {
	t.Parallel()
	type record struct {
		id     string
		name   string
		status string
	}
	var mu sync.Mutex
	byProject := map[string]map[string]record{}
	byKey := map[string]string{}
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		if r.URL.Path != "/prefix/v1/agents" || r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		key := r.Header.Get("X-Controller-Key")
		project := strings.TrimPrefix(key, "key-")
		if project == key || r.Header.Get("Idempotency-Key") == "" {
			t.Errorf("missing credentials or idempotency key")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var body struct {
			ExternalAgentID string `json:"external_agent_id"`
			Name            string `json:"name"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode request: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		requestID := project + "/" + r.Header.Get("Idempotency-Key")
		fingerprint := body.ExternalAgentID + "/" + body.Name
		if previous, exists := byKey[requestID]; exists && previous != fingerprint {
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(APIError{Code: "IDEMPOTENCY_CONFLICT", Message: "request conflicts with previous request"})
			return
		}
		byKey[requestID] = fingerprint
		if byProject[project] == nil {
			byProject[project] = map[string]record{}
		}
		item, exists := byProject[project][body.ExternalAgentID]
		if !exists {
			item = record{id: "aag_" + project, name: body.Name, status: "ACTIVE"}
			byProject[project][body.ExternalAgentID] = item
		}
		if exists {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusCreated)
		}
		_ = json.NewEncoder(w).Encode(AgentAssociation{
			AuthAgentID: item.id, ProjectID: project, ExternalAgentID: body.ExternalAgentID,
			Name: item.name, Status: item.status, CreatedAt: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), Replayed: exists,
		})
	}))
	defer server.Close()
	newClient := func(project string) *ControllerClient {
		client, err := NewControllerClient(ControllerConfig{BaseURL: server.URL + "/prefix", ControllerKey: "key-" + project, ProjectID: project})
		if err != nil {
			t.Fatal(err)
		}
		return client
	}
	client := newClient("project-a")
	first, err := client.RegisterAgent(context.Background(), RegisterAgentRequest{ExternalAgentID: "Agent-A", Name: "First", IdempotencyKey: "op-1"})
	if err != nil || first.Replayed || first.AuthAgentID == "" {
		t.Fatalf("first register: %+v, %v", first, err)
	}
	// Response loss: the same request and idempotency key return the original ID.
	replayed, err := client.RegisterAgent(context.Background(), RegisterAgentRequest{ExternalAgentID: "Agent-A", Name: "First", IdempotencyKey: "op-1"})
	if err != nil || !replayed.Replayed || replayed.AuthAgentID != first.AuthAgentID {
		t.Fatalf("replay: %+v, %v", replayed, err)
	}
	// A local DB save failure can lose the request key. The stable business ID
	// still recovers the association, even with a newer display name.
	mu.Lock()
	byProject["project-a"]["Agent-A"] = record{id: first.AuthAgentID, name: "First", status: "PAUSED"}
	mu.Unlock()
	recovered, err := client.RecoverAgent(context.Background(), "Agent-A", "Renamed")
	if err != nil || recovered.AuthAgentID != first.AuthAgentID || recovered.Name != "First" || recovered.Status != "PAUSED" || !recovered.Replayed {
		t.Fatalf("recover: %+v, %v", recovered, err)
	}
	_, err = client.RegisterAgent(context.Background(), RegisterAgentRequest{ExternalAgentID: "Agent-A", Name: "Changed", IdempotencyKey: "op-1"})
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusConflict || apiErr.Code != "IDEMPOTENCY_CONFLICT" {
		t.Fatalf("expected conflict, got %v", err)
	}
	other, err := newClient("project-b").RecoverAgent(context.Background(), "Agent-A", "Other")
	if err != nil || other.ProjectID != "project-b" || other.AuthAgentID == first.AuthAgentID || other.Replayed {
		t.Fatalf("project isolation: %+v, %v", other, err)
	}
	if calls != 5 {
		t.Fatalf("request count = %d, want 5", calls)
	}
}

func TestRegisterRejectsInvalidInputsAndResponse(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(AgentAssociation{AuthAgentID: "aag_other", ProjectID: "other", ExternalAgentID: "Agent-A", Name: "A", Status: "ACTIVE", CreatedAt: time.Now(), Replayed: true})
	}))
	defer server.Close()
	client, err := NewControllerClient(ControllerConfig{BaseURL: server.URL, ControllerKey: "key", ProjectID: "project-a"})
	if err != nil {
		t.Fatal(err)
	}
	for _, in := range []RegisterAgentRequest{
		{ExternalAgentID: " Agent-A", Name: "A"},
		{ExternalAgentID: "Agent-A", Name: ""},
		{ExternalAgentID: "Agent-A", Name: "A", IdempotencyKey: "bad\nkey"},
		{ExternalAgentID: "Agent-A", Name: "A", IdempotencyKey: " key "},
	} {
		if _, err := client.RegisterAgent(context.Background(), in); err == nil {
			t.Fatalf("accepted invalid request: %+v", in)
		}
	}
	if _, err := client.RecoverAgent(context.Background(), "Agent-A", "A"); err == nil || !strings.Contains(err.Error(), "contract") {
		t.Fatalf("accepted wrong-project response: %v", err)
	}
	if _, err := NewControllerClient(ControllerConfig{BaseURL: "https://user:pass@example.com", ControllerKey: "key", ProjectID: "project-a"}); err == nil {
		t.Fatal("accepted URL credentials")
	}
}

func TestControllerKeyIsNotForwardedThroughRedirect(t *testing.T) {
	t.Parallel()
	var forwarded bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded = r.Header.Get("X-Controller-Key") != ""
	}))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	client, err := NewControllerClient(ControllerConfig{BaseURL: redirect.URL, ControllerKey: "secret", ProjectID: "project-a"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.RecoverAgent(context.Background(), "Agent-A", "A"); err == nil {
		t.Fatal("accepted redirect as a registration response")
	}
	if forwarded {
		t.Fatal("Controller Key was forwarded through redirect")
	}
}

func TestRecoverAfterRemoteCommitAndLostResponse(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	committed := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		first := !committed
		committed = true
		mu.Unlock()
		if first {
			connection, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Errorf("hijack: %v", err)
				return
			}
			_ = connection.Close() // The server committed, but the client saw no response.
			return
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(AgentAssociation{
			AuthAgentID: "aag_original", ProjectID: "project-a", ExternalAgentID: "Agent-A",
			Name: "First", Status: "ACTIVE", CreatedAt: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), Replayed: true,
		})
	}))
	defer server.Close()
	client, err := NewControllerClient(ControllerConfig{BaseURL: server.URL, ControllerKey: "secret", ProjectID: "project-a"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.RegisterAgent(context.Background(), RegisterAgentRequest{ExternalAgentID: "Agent-A", Name: "First", IdempotencyKey: "original-op"}); err == nil {
		t.Fatal("expected lost-response error")
	}
	recovered, err := client.RecoverAgent(context.Background(), "Agent-A", "First")
	if err != nil || recovered.AuthAgentID != "aag_original" || !recovered.Replayed {
		t.Fatalf("recovery: %+v, %v", recovered, err)
	}
}
