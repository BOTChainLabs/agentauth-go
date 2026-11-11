// Package agentauth provides server-side clients for the AgentAuth API.
// Controller credentials must remain in a trusted backend, never in an Agent Runtime.
package agentauth

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const maxResponseBytes = 1 << 20

// ControllerConfig configures the trusted-backend client. ProjectID is the
// expected project of ControllerKey, not a value sent as an API parameter.
type ControllerConfig struct {
	BaseURL       string
	ControllerKey string
	ProjectID     string
	HTTPClient    *http.Client
}

// ControllerClient only holds control-plane credentials. Do not share it with
// an Agent Runtime or serialize it into application responses.
type ControllerClient struct {
	baseURL       string
	endpoint      string
	controllerKey string
	projectID     string
	httpClient    *http.Client
}

// NewControllerClient validates configuration before any network call.
func NewControllerClient(cfg ControllerConfig) (*ControllerClient, error) {
	base, err := url.Parse(cfg.BaseURL)
	if err != nil || base == nil || (base.Scheme != "http" && base.Scheme != "https") ||
		base.Host == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" {
		return nil, errors.New("agentauth: BaseURL must be an HTTP(S) URL without credentials, query, or fragment")
	}
	if cfg.ControllerKey == "" || strings.TrimSpace(cfg.ControllerKey) != cfg.ControllerKey ||
		strings.ContainsAny(cfg.ControllerKey, "\r\n") {
		return nil, errors.New("agentauth: ControllerKey is required")
	}
	if cfg.ProjectID == "" || len(cfg.ProjectID) > 64 {
		return nil, errors.New("agentauth: ProjectID is required and must be at most 64 characters")
	}
	for _, r := range cfg.ProjectID {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' || r == '-') {
			return nil, errors.New("agentauth: ProjectID must contain only lowercase letters, digits, '_' or '-'")
		}
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	// A Controller Key must not be forwarded to a redirect target, including
	// one chosen by a compromised or misconfigured API endpoint.
	clientCopy := *client
	clientCopy.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	endpoint, err := url.JoinPath(strings.TrimRight(base.String(), "/"), "v1", "agents")
	if err != nil {
		return nil, fmt.Errorf("agentauth: build endpoint: %w", err)
	}
	return &ControllerClient{baseURL: strings.TrimRight(base.String(), "/"), endpoint: endpoint, controllerKey: cfg.ControllerKey, projectID: cfg.ProjectID, httpClient: &clientCopy}, nil
}

// RegisterAgentRequest identifies an existing business Agent. Reuse the same
// IdempotencyKey and body when retrying an uncertain HTTP outcome. If the key
// was lost, leave it empty: the server's project-and-external-ID uniqueness
// still recovers the original association.
type RegisterAgentRequest struct {
	ExternalAgentID string
	Name            string
	IdempotencyKey  string
}

// AgentAssociation is the server's current association state. Replayed means
// an existing association was returned; it does not imply execution readiness.
type AgentAssociation struct {
	AuthAgentID     string    `json:"auth_agent_id"`
	ProjectID       string    `json:"project_id"`
	ExternalAgentID string    `json:"external_agent_id"`
	Name            string    `json:"name"`
	Status          string    `json:"status"`
	CreatedAt       time.Time `json:"created_at"`
	Replayed        bool      `json:"replayed"`
}

// APIError exposes the AgentAuth error contract without requiring a private
// service package. Use errors.As to inspect StatusCode, Code, and Retryable.
type APIError struct {
	StatusCode int    `json:"-"`
	Code       string `json:"error_code"`
	Message    string `json:"error_message"`
	RequestID  string `json:"request_id"`
	Retryable  bool   `json:"retryable"`
}

func (e *APIError) Error() string {
	return fmt.Sprintf("agentauth: HTTP %d %s: %s", e.StatusCode, e.Code, e.Message)
}

// RegisterAgent creates or retrieves the single association for this Project
// and external Agent ID. It never changes an existing name or paused status.
// It does not create a resource binding or Session.
func (c *ControllerClient) RegisterAgent(ctx context.Context, in RegisterAgentRequest) (AgentAssociation, error) {
	if c == nil {
		return AgentAssociation{}, errors.New("agentauth: nil ControllerClient")
	}
	if err := validateLabel("ExternalAgentID", in.ExternalAgentID); err != nil {
		return AgentAssociation{}, err
	}
	if err := validateLabel("Name", in.Name); err != nil {
		return AgentAssociation{}, err
	}
	key := in.IdempotencyKey
	if key == "" {
		var random [16]byte
		if _, err := rand.Read(random[:]); err != nil {
			return AgentAssociation{}, fmt.Errorf("agentauth: generate idempotency key: %w", err)
		}
		key = "register-agent-" + hex.EncodeToString(random[:])
	}
	if len(key) > 128 || strings.TrimSpace(key) != key {
		return AgentAssociation{}, errors.New("agentauth: IdempotencyKey must be 1..128 printable ASCII characters without surrounding whitespace")
	}
	for i := 0; i < len(key); i++ {
		if key[i] < 0x20 || key[i] > 0x7e {
			return AgentAssociation{}, errors.New("agentauth: IdempotencyKey must contain only printable ASCII")
		}
	}
	body, err := json.Marshal(struct {
		ExternalAgentID string `json:"external_agent_id"`
		Name            string `json:"name"`
	}{in.ExternalAgentID, in.Name})
	if err != nil {
		return AgentAssociation{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return AgentAssociation{}, fmt.Errorf("agentauth: build register request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Controller-Key", c.controllerKey)
	req.Header.Set("Idempotency-Key", key)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return AgentAssociation{}, fmt.Errorf("agentauth: register agent: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return AgentAssociation{}, fmt.Errorf("agentauth: read register response: %w", err)
	}
	if len(raw) > maxResponseBytes {
		return AgentAssociation{}, errors.New("agentauth: register response too large")
	}
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		apiErr := &APIError{StatusCode: resp.StatusCode}
		if json.Unmarshal(raw, apiErr) != nil || apiErr.Code == "" {
			return AgentAssociation{}, fmt.Errorf("agentauth: register agent HTTP %d: invalid error response", resp.StatusCode)
		}
		return AgentAssociation{}, apiErr
	}
	var association AgentAssociation
	if err := json.Unmarshal(raw, &association); err != nil {
		return AgentAssociation{}, fmt.Errorf("agentauth: decode register response: %w", err)
	}
	if association.ProjectID != c.projectID || association.ExternalAgentID != in.ExternalAgentID ||
		association.AuthAgentID == "" || (association.Status != "ACTIVE" && association.Status != "PAUSED") ||
		association.CreatedAt.IsZero() || association.Replayed != (resp.StatusCode == http.StatusOK) {
		return AgentAssociation{}, errors.New("agentauth: register response violates association contract")
	}
	return association, nil
}

// RecoverAgent retrieves the association after the caller failed to persist
// its auth_agent_id. The caller must supply the original Project credential
// and stable external ID; a new idempotency key is intentionally used.
func (c *ControllerClient) RecoverAgent(ctx context.Context, externalAgentID, name string) (AgentAssociation, error) {
	return c.RegisterAgent(ctx, RegisterAgentRequest{ExternalAgentID: externalAgentID, Name: name})
}

func validateLabel(field, value string) error {
	if value == "" || !utf8.ValidString(value) || utf8.RuneCountInString(value) > 128 {
		return fmt.Errorf("agentauth: %s must be 1..128 valid UTF-8 characters", field)
	}
	runes := []rune(value)
	if unicode.IsSpace(runes[0]) || unicode.IsSpace(runes[len(runes)-1]) {
		return fmt.Errorf("agentauth: %s must not have leading or trailing whitespace", field)
	}
	for _, r := range runes {
		if unicode.IsControl(r) {
			return fmt.Errorf("agentauth: %s must not contain control characters", field)
		}
	}
	return nil
}
