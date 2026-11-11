package agentauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ResourceSpec is the payment resource approved by its owner. Wallet payer is
// supplied by the Wallet assertion, not by the caller creating a challenge.
type ResourceSpec struct {
	ResourceType string `json:"resource_type"`
	Network      string `json:"network"`
	Payer        string `json:"payer,omitempty"`
	WalletID     string `json:"wallet_id,omitempty"`
	Asset        string `json:"asset"`
	// These fields appear only in verified Wallet binding responses.
	WalletProjectID string `json:"wallet_project_id,omitempty"`
	ExternalAgentID string `json:"external_agent_id,omitempty"`
}

type ServiceRule struct {
	ServiceID     string `json:"service_id"`
	ConfigVersion int    `json:"config_version"`
}

type Grant struct {
	ActionType string        `json:"action_type"`
	Services   []ServiceRule `json:"services"`
}

type Limits struct {
	PerActionLimit   string `json:"per_action_limit"`
	DailyLimit       string `json:"daily_limit"`
	LifetimeLimit    string `json:"lifetime_limit"`
	MaxInflightUnits string `json:"max_inflight_units"`
	MaxInflightCount int    `json:"max_inflight_count"`
}

type Budget struct {
	Unit              string `json:"unit"`
	Scope             string `json:"scope"`
	ResourceBindingID string `json:"resource_binding_id"`
	BudgetDate        string `json:"budget_date"`
	DailyLimit        string `json:"daily_limit"`
	DailyCommitted    string `json:"daily_committed"`
	DailyReserved     string `json:"daily_reserved"`
	DailyAvailable    string `json:"daily_available"`
	LifetimeLimit     string `json:"lifetime_limit"`
	LifetimeCommitted string `json:"lifetime_committed"`
	LifetimeReserved  string `json:"lifetime_reserved"`
	LifetimeAvailable string `json:"lifetime_available"`
	MaxInflightUnits  string `json:"max_inflight_units"`
	InflightCount     int    `json:"inflight_count"`
	MaxInflightCount  int    `json:"max_inflight_count"`
}

type BindingChallengeRequest struct {
	Resource       ResourceSpec `json:"resource"`
	Grant          Grant        `json:"grant"`
	GrantLimits    Limits       `json:"grant_limits"`
	ValidUntil     time.Time    `json:"valid_until"`
	IdempotencyKey string       `json:"-"`
}

type BindingChallenge struct {
	ChallengeToken     string    `json:"challenge_token"`
	ChallengeID        string    `json:"challenge_id"`
	ChallengeExpiresAt time.Time `json:"challenge_expires_at"`
	Message            string    `json:"message"`
	ResourceHash       string    `json:"resource_hash"`
	GrantHash          string    `json:"grant_hash"`
	GrantLimitsHash    string    `json:"grant_limits_hash"`
	Replayed           bool      `json:"replayed"`
}

type CreateBindingRequest struct {
	ChallengeToken           string       `json:"challenge_token"`
	Resource                 ResourceSpec `json:"resource"`
	Grant                    Grant        `json:"grant"`
	GrantLimits              Limits       `json:"grant_limits"`
	EOASignature             string       `json:"eoa_signature,omitempty"`
	ResourceControlAssertion string       `json:"resource_control_assertion,omitempty"`
	IdempotencyKey           string       `json:"-"`
}

type ResourceBinding struct {
	ResourceBindingID string       `json:"resource_binding_id"`
	AuthAgentID       string       `json:"auth_agent_id"`
	ProjectID         string       `json:"project_id"`
	Resource          ResourceSpec `json:"resource"`
	Grant             Grant        `json:"grant"`
	GrantLimits       Limits       `json:"grant_limits"`
	Budget            *Budget      `json:"budget,omitempty"`
	Version           int          `json:"version"`
	Status            string       `json:"status"`
	ValidUntil        time.Time    `json:"valid_until"`
	CreatedAt         time.Time    `json:"created_at"`
	Replayed          bool         `json:"replayed,omitempty"`
}

type BindingPage struct {
	Items      []ResourceBinding `json:"items"`
	NextCursor *string           `json:"next_cursor"`
}

type RevokedBinding struct {
	ResourceBindingID string    `json:"resource_binding_id"`
	Status            string    `json:"status"`
	RevokedAt         time.Time `json:"revoked_at"`
	Replayed          bool      `json:"replayed"`
}

// CreateBindingChallenge returns the exact message the EOA owner must sign.
// A challenge alone grants no permission.
func (c *ControllerClient) CreateBindingChallenge(ctx context.Context, agentID string, in BindingChallengeRequest) (BindingChallenge, error) {
	var out BindingChallenge
	if !validID(agentID, "aag_") {
		return out, errors.New("agentauth: invalid Agent ID")
	}
	if err := c.call(ctx, http.MethodPost, "agents/"+agentID+"/resource-binding-challenges", in.IdempotencyKey, in, &out, http.StatusCreated, http.StatusOK); err != nil {
		return out, err
	}
	if out.ChallengeToken == "" || out.Message == "" || out.ChallengeID == "" {
		return out, errors.New("agentauth: incomplete challenge response")
	}
	return out, nil
}

func (c *ControllerClient) CreateBinding(ctx context.Context, agentID string, in CreateBindingRequest) (ResourceBinding, error) {
	var out ResourceBinding
	if !validID(agentID, "aag_") {
		return out, errors.New("agentauth: invalid Agent ID")
	}
	if (in.EOASignature == "") == (in.ResourceControlAssertion == "") {
		return out, errors.New("agentauth: exactly one resource control proof is required")
	}
	if err := c.call(ctx, http.MethodPost, "agents/"+agentID+"/resource-bindings", in.IdempotencyKey, in, &out, http.StatusCreated, http.StatusOK); err != nil {
		return out, err
	}
	return out, c.checkBinding(out, agentID)
}

func (c *ControllerClient) GetBinding(ctx context.Context, bindingID string) (ResourceBinding, error) {
	var out ResourceBinding
	if !validID(bindingID, "arb_") {
		return out, errors.New("agentauth: invalid binding ID")
	}
	if err := c.call(ctx, http.MethodGet, "resource-bindings/"+bindingID, "", nil, &out, http.StatusOK); err != nil {
		return out, err
	}
	if out.ResourceBindingID != bindingID {
		return out, errors.New("agentauth: binding response ID mismatch")
	}
	return out, c.checkBinding(out, "")
}

func (c *ControllerClient) ListBindings(ctx context.Context, agentID, cursor string, limit int) (BindingPage, error) {
	var out BindingPage
	if !validID(agentID, "aag_") {
		return out, errors.New("agentauth: invalid Agent ID")
	}
	path, err := withPage("agents/"+agentID+"/resource-bindings", cursor, limit)
	if err != nil {
		return out, err
	}
	if err = c.call(ctx, http.MethodGet, path, "", nil, &out, http.StatusOK); err != nil {
		return out, err
	}
	for _, item := range out.Items {
		if err := c.checkBinding(item, agentID); err != nil {
			return BindingPage{}, err
		}
	}
	return out, nil
}

func (c *ControllerClient) RevokeBinding(ctx context.Context, bindingID, reason, key string) (RevokedBinding, error) {
	var out RevokedBinding
	if !validID(bindingID, "arb_") {
		return out, errors.New("agentauth: invalid binding ID")
	}
	if reason == "" {
		return out, errors.New("agentauth: revocation reason is required")
	}
	err := c.call(ctx, http.MethodPost, "resource-bindings/"+bindingID+":revoke", key, struct {
		Reason string `json:"reason"`
	}{reason}, &out, http.StatusOK)
	if err == nil && (out.ResourceBindingID != bindingID || out.Status != "REVOKED") {
		err = errors.New("agentauth: invalid revoke response")
	}
	return out, err
}

func (c *ControllerClient) checkBinding(v ResourceBinding, agentID string) error {
	if v.ProjectID != c.projectID || v.ResourceBindingID == "" || v.AuthAgentID == "" || (agentID != "" && v.AuthAgentID != agentID) {
		return errors.New("agentauth: binding response violates project or agent contract")
	}
	return nil
}

// call is shared by control-plane operations. Callers own the business key so
// a lost response can be replayed with precisely the same request body.
func (c *ControllerClient) call(ctx context.Context, method, path, key string, body, out any, success ...int) error {
	if c == nil {
		return errors.New("agentauth: nil ControllerClient")
	}
	pathOnly, query, _ := strings.Cut(path, "?")
	for _, part := range strings.Split(pathOnly, "/") {
		if part == "" || part == "." || part == ".." || strings.ContainsAny(part, "?#%\\") {
			return errors.New("agentauth: invalid path identifier")
		}
	}
	if method != http.MethodGet {
		if err := validateKey(key); err != nil {
			return err
		}
	} else if key != "" {
		return errors.New("agentauth: GET must not carry an idempotency key")
	}
	target, err := url.JoinPath(c.baseURL, "v1", pathOnly)
	if err != nil {
		return err
	}
	if query != "" {
		target += "?" + query
	}
	var payload []byte
	if body != nil {
		payload, err = json.Marshal(body)
		if err != nil {
			return err
		}
		if len(payload) > 64<<10 {
			return errors.New("agentauth: request body too large")
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("X-Controller-Key", c.controllerKey)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if key != "" {
		req.Header.Set("Idempotency-Key", key)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("agentauth: control request: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return err
	}
	if len(raw) > maxResponseBytes {
		return errors.New("agentauth: response too large")
	}
	for _, status := range success {
		if resp.StatusCode == status {
			if err := json.Unmarshal(raw, out); err != nil {
				return fmt.Errorf("agentauth: decode response: %w", err)
			}
			return nil
		}
	}
	apiErr := &APIError{StatusCode: resp.StatusCode}
	if json.Unmarshal(raw, apiErr) == nil && apiErr.Code != "" {
		return apiErr
	}
	return fmt.Errorf("agentauth: HTTP %d: invalid error response", resp.StatusCode)
}

func validateKey(key string) error {
	if len(key) < 1 || len(key) > 128 || strings.TrimSpace(key) != key {
		return errors.New("agentauth: IdempotencyKey must be 1..128 printable ASCII characters")
	}
	for i := range key {
		if key[i] < 0x20 || key[i] > 0x7e {
			return errors.New("agentauth: IdempotencyKey must contain only printable ASCII")
		}
	}
	return nil
}

func withPage(path, cursor string, limit int) (string, error) {
	if limit < 0 || limit > 100 {
		return "", errors.New("agentauth: limit must be 1..100 or zero for default")
	}
	query := url.Values{}
	if cursor != "" {
		query.Set("cursor", cursor)
	}
	if limit != 0 {
		query.Set("limit", fmt.Sprint(limit))
	}
	if len(query) == 0 {
		return path, nil
	}
	return path + "?" + query.Encode(), nil
}
