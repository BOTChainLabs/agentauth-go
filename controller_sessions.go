package agentauth

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type RuntimeCredential struct {
	Algorithm string `json:"algorithm"`
	PublicKey string `json:"public_key"`
}

type CreateSessionRequest struct {
	ResourceBindingID string            `json:"resource_binding_id"`
	RuntimeCredential RuntimeCredential `json:"runtime_credential"`
	Rules             Grant             `json:"rules"`
	Limits            Limits            `json:"limits"`
	ValidFrom         *time.Time        `json:"valid_from,omitempty"`
	ValidUntil        time.Time         `json:"valid_until"`
	IdempotencyKey    string            `json:"-"`
}

type Session struct {
	SessionID         string        `json:"session_id"`
	AuthAgentID       string        `json:"auth_agent_id"`
	ResourceBindingID string        `json:"resource_binding_id"`
	Status            string        `json:"status"`
	RuntimeThumbprint string        `json:"runtime_thumbprint"`
	PolicyDigest      string        `json:"policy_digest"`
	Rules             Grant         `json:"rules"`
	Limits            Limits        `json:"limits"`
	GrantLimits       Limits        `json:"grant_limits"`
	Unit              string        `json:"unit"`
	ValidFrom         time.Time     `json:"valid_from"`
	ValidUntil        time.Time     `json:"valid_until"`
	CreatedAt         time.Time     `json:"created_at"`
	Network           string        `json:"network,omitempty"`
	Asset             string        `json:"asset,omitempty"`
	Payer             string        `json:"payer,omitempty"`
	Resource          *ResourceSpec `json:"resource,omitempty"`
	Budget            *Budget       `json:"budget,omitempty"`
	ActivatedAt       *time.Time    `json:"activated_at,omitempty"`
	UpdatedAt         *time.Time    `json:"updated_at,omitempty"`
	Replayed          bool          `json:"replayed,omitempty"`
}

type SessionStatus struct {
	SessionID string    `json:"session_id"`
	Status    string    `json:"status"`
	UpdatedAt time.Time `json:"updated_at"`
	Replayed  bool      `json:"replayed"`
}

type SessionSummary struct {
	SessionID         string    `json:"session_id"`
	Status            string    `json:"status"`
	ActionType        string    `json:"action_type"`
	ResourceBindingID string    `json:"resource_binding_id"`
	ValidUntil        time.Time `json:"valid_until"`
	Budget            Budget    `json:"budget"`
}

type SessionPage struct {
	Items      []SessionSummary `json:"items"`
	NextCursor *string          `json:"next_cursor"`
}

type IntegrationComponent struct {
	Service         string     `json:"service"`
	Status          string     `json:"status"`
	ObservedAt      time.Time  `json:"observed_at"`
	BindingVersion  int        `json:"binding_version,omitempty"`
	ReasonCode      string     `json:"reason_code,omitempty"`
	Payer           string     `json:"payer,omitempty"`
	Network         string     `json:"network,omitempty"`
	Asset           string     `json:"asset,omitempty"`
	ServiceID       string     `json:"service_id,omitempty"`
	ConfigVersion   int        `json:"config_version,omitempty"`
	WalletID        string     `json:"wallet_id,omitempty"`
	AuthMode        string     `json:"auth_mode,omitempty"`
	ConfigUpdatedAt *time.Time `json:"config_updated_at,omitempty"`
}

type IntegrationStatus struct {
	Status            string                 `json:"status"`
	CheckedAt         time.Time              `json:"checked_at"`
	AuthProjectID     string                 `json:"auth_project_id"`
	AuthAgentID       string                 `json:"auth_agent_id"`
	ResourceBindingID string                 `json:"resource_binding_id"`
	SessionID         string                 `json:"session_id"`
	Components        []IntegrationComponent `json:"components"`
}

// GetIntegrationStatus is a read-only cross-service snapshot. It does not
// enable payment protection and does not authorize any execution.
func (c *ControllerClient) GetIntegrationStatus(ctx context.Context, sessionID string) (IntegrationStatus, error) {
	var out IntegrationStatus
	if !validID(sessionID, "ses_") {
		return out, errors.New("agentauth: invalid Session ID")
	}
	err := c.call(ctx, http.MethodGet, "sessions/"+sessionID+"/integration-status", "", nil, &out, http.StatusOK)
	if err == nil && (out.SessionID != sessionID || out.AuthProjectID != c.projectID) {
		err = errors.New("agentauth: integration status violates project or session contract")
	}
	return out, err
}

func (c *ControllerClient) CreateSession(ctx context.Context, agentID string, in CreateSessionRequest) (Session, error) {
	var out Session
	if !validID(agentID, "aag_") || !validID(in.ResourceBindingID, "arb_") {
		return out, errors.New("agentauth: invalid Agent or binding ID")
	}
	publicKey, decodeErr := base64.RawURLEncoding.DecodeString(in.RuntimeCredential.PublicKey)
	if in.RuntimeCredential.Algorithm != "Ed25519" || decodeErr != nil || len(publicKey) != 32 || base64.RawURLEncoding.EncodeToString(publicKey) != in.RuntimeCredential.PublicKey {
		return out, errors.New("agentauth: Ed25519 public credential required")
	}
	err := c.call(ctx, http.MethodPost, "agents/"+agentID+"/sessions", in.IdempotencyKey, in, &out, http.StatusCreated, http.StatusOK)
	if err == nil && (out.AuthAgentID != agentID || out.ResourceBindingID != in.ResourceBindingID || out.SessionID == "" || out.PolicyDigest == "") {
		err = errors.New("agentauth: session response violates request contract")
	}
	return out, err
}

func (c *ControllerClient) GetSession(ctx context.Context, sessionID string) (Session, error) {
	var out Session
	if !validID(sessionID, "ses_") {
		return out, errors.New("agentauth: invalid Session ID")
	}
	err := c.call(ctx, http.MethodGet, "sessions/"+sessionID, "", nil, &out, http.StatusOK)
	if err == nil && out.SessionID != sessionID {
		err = errors.New("agentauth: session response ID mismatch")
	}
	return out, err
}

func (c *ControllerClient) ListSessions(ctx context.Context, agentID, status, cursor string, limit int) (SessionPage, error) {
	var out SessionPage
	if !validID(agentID, "aag_") {
		return out, errors.New("agentauth: invalid Agent ID")
	}
	path, err := withPage("agents/"+agentID+"/sessions", cursor, limit)
	if err != nil {
		return out, err
	}
	if status != "" {
		if status != "DRAFT" && status != "ACTIVE" && status != "PAUSED" && status != "REVOKED" && status != "EXPIRED" {
			return out, errors.New("agentauth: invalid session status filter")
		}
		sep := "?"
		if strings.Contains(path, "?") {
			sep = "&"
		}
		path += sep + "status=" + url.QueryEscape(status)
	}
	err = c.call(ctx, http.MethodGet, path, "", nil, &out, http.StatusOK)
	return out, err
}

func (c *ControllerClient) ActivateSession(ctx context.Context, sessionID, approvedDigest, key string) (SessionStatus, error) {
	return c.sessionDigestAction(ctx, sessionID, "activate", approvedDigest, key)
}

func (c *ControllerClient) ResumeSession(ctx context.Context, sessionID, approvedDigest, key string) (SessionStatus, error) {
	return c.sessionDigestAction(ctx, sessionID, "resume", approvedDigest, key)
}

func (c *ControllerClient) sessionDigestAction(ctx context.Context, sessionID, verb, digest, key string) (SessionStatus, error) {
	var out SessionStatus
	if !validID(sessionID, "ses_") {
		return out, errors.New("agentauth: invalid Session ID")
	}
	if digest == "" {
		return out, errors.New("agentauth: approved policy digest is required")
	}
	err := c.call(ctx, http.MethodPost, "sessions/"+sessionID+":"+verb, key, struct {
		PolicyDigest string `json:"policy_digest"`
	}{digest}, &out, http.StatusOK)
	if err == nil && out.SessionID != sessionID {
		err = errors.New("agentauth: session status response ID mismatch")
	}
	return out, err
}

func (c *ControllerClient) PauseSession(ctx context.Context, sessionID, reason, key string) (SessionStatus, error) {
	return c.sessionReasonAction(ctx, sessionID, "pause", reason, key)
}

func (c *ControllerClient) RevokeSession(ctx context.Context, sessionID, reason, key string) (SessionStatus, error) {
	return c.sessionReasonAction(ctx, sessionID, "revoke", reason, key)
}

func (c *ControllerClient) sessionReasonAction(ctx context.Context, sessionID, verb, reason, key string) (SessionStatus, error) {
	var out SessionStatus
	if !validID(sessionID, "ses_") {
		return out, errors.New("agentauth: invalid Session ID")
	}
	if reason == "" {
		return out, errors.New("agentauth: reason is required")
	}
	err := c.call(ctx, http.MethodPost, "sessions/"+sessionID+":"+verb, key, struct {
		Reason string `json:"reason"`
	}{reason}, &out, http.StatusOK)
	if err == nil && out.SessionID != sessionID {
		err = errors.New("agentauth: session status response ID mismatch")
	}
	return out, err
}
