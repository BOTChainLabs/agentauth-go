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

type RuntimeConfig struct {
	AuthURL     string
	AgentPayURL string
	Signer      *RuntimeSigner
	HTTPClient  *http.Client
	// RetryAttempts is the total number of attempts for idempotent Runtime
	// writes (1..3). Zero uses two attempts.
	RetryAttempts int
}

// RuntimeClient has no control-plane credential or administrative capability.
type RuntimeClient struct {
	authURL, agentPayURL string
	signer               *RuntimeSigner
	httpClient           *http.Client
	retryAttempts        int
}

func NewRuntimeClient(cfg RuntimeConfig) (*RuntimeClient, error) {
	if cfg.Signer == nil {
		return nil, errors.New("agentauth: RuntimeSigner required")
	}
	authURL, err := validateBaseURL(cfg.AuthURL)
	if err != nil {
		return nil, err
	}
	payURL := ""
	if cfg.AgentPayURL != "" {
		payURL, err = validateBaseURL(cfg.AgentPayURL)
		if err != nil {
			return nil, err
		}
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	copyClient := *client
	copyClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	attempts := cfg.RetryAttempts
	if attempts == 0 {
		attempts = 2
	}
	if attempts < 1 || attempts > 3 {
		return nil, errors.New("agentauth: RetryAttempts must be 1..3")
	}
	return &RuntimeClient{authURL: authURL, agentPayURL: payURL, signer: cfg.Signer, httpClient: &copyClient, retryAttempts: attempts}, nil
}

func validateBaseURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u == nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("agentauth: invalid HTTP(S) base URL")
	}
	return strings.TrimRight(u.String(), "/"), nil
}

type AuthorizeResult struct {
	Decision           string    `json:"decision"`
	ReasonCode         string    `json:"reason_code,omitempty"`
	SessionID          string    `json:"session_id,omitempty"`
	AuthorizationID    string    `json:"authorization_id,omitempty"`
	IntentHash         string    `json:"intent_hash,omitempty"`
	AuthorizationProof string    `json:"authorization_proof,omitempty"`
	ProofExpiresAt     time.Time `json:"proof_expires_at,omitempty"`
	ClaimDeadline      time.Time `json:"claim_deadline,omitempty"`
	Budget             *Budget   `json:"budget,omitempty"`
	GrantLimits        *Limits   `json:"grant_limits,omitempty"`
	Status             string    `json:"status,omitempty"`
	ExecutionID        *string   `json:"execution_id,omitempty"`
	Replayed           bool      `json:"replayed"`
}

func (r AuthorizeResult) IsAllowed() bool { return r.Decision == "ALLOW" && r.AuthorizationProof != "" }
func (r AuthorizeResult) IsDenied() bool  { return r.Decision == "DENY" }
func (r AuthorizeResult) IsStatusReplay() bool {
	return r.Decision == "" && r.Replayed && r.AuthorizationID != "" && r.Status != ""
}

// AuthorizePayment accepts the original AgentPay Context and a stable key for
// one business payment. Retry with those same values after uncertain outcomes.
func (c *RuntimeClient) AuthorizePayment(ctx context.Context, paymentContextToken, businessKey string) (AuthorizeResult, error) {
	var out AuthorizeResult
	if paymentContextToken == "" {
		return out, errors.New("agentauth: payment context token required")
	}
	if err := validateKey(businessKey); err != nil {
		return out, err
	}
	body := struct {
		ActionType          string `json:"action_type"`
		PaymentContextToken string `json:"payment_context_token"`
	}{"X402_PAYMENT", paymentContextToken}
	err := c.callWithSafeRetry(ctx, c.authURL, "auth", "authorizations:authorize", businessKey, body, &out, http.StatusOK)
	if err != nil {
		return out, err
	}
	if !out.IsAllowed() && !out.IsDenied() && !out.IsStatusReplay() {
		return out, errors.New("agentauth: unknown Authorize response shape")
	}
	return out, nil
}

type Authorization struct {
	AuthorizationID string    `json:"authorization_id"`
	SessionID       string    `json:"session_id"`
	AuthAgentID     string    `json:"auth_agent_id"`
	ActionType      string    `json:"action_type"`
	Status          string    `json:"status"`
	IntentHash      string    `json:"intent_hash"`
	Units           string    `json:"units"`
	Unit            string    `json:"unit"`
	ClaimDeadline   time.Time `json:"claim_deadline"`
	ProofExpiresAt  time.Time `json:"proof_expires_at"`
	ExecutorService string    `json:"executor_service"`
	ExecutionID     *string   `json:"execution_id"`
	ResultReason    *string   `json:"result_reason"`
	PaymentOrderID  *string   `json:"payment_order_id"`
	TxHash          *string   `json:"tx_hash"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

func (c *RuntimeClient) GetAuthorization(ctx context.Context, id string) (Authorization, error) {
	var out Authorization
	if !validID(id, "aat_") {
		return out, errors.New("agentauth: invalid Authorization ID")
	}
	err := c.call(ctx, c.authURL, "auth", http.MethodGet, "authorizations/"+id, "", nil, "", &out, http.StatusOK)
	if err == nil && (out.AuthorizationID != id || out.SessionID != c.signer.sessionID) {
		err = errors.New("agentauth: authorization response ID mismatch")
	}
	return out, err
}

type RequestBinding struct {
	Method             string `json:"method"`
	ResourceURL        string `json:"resource_url"`
	RequestHash        string `json:"request_hash"`
	RequestHashVersion string `json:"request_hash_version"`
}

type PaymentContextRequest struct {
	ResourceBindingID string          `json:"resource_binding_id"`
	ServiceID         string          `json:"service_id"`
	ConfigVersion     int             `json:"config_version"`
	PaymentRequired   json.RawMessage `json:"payment_required"`
	RequestBinding    RequestBinding  `json:"request_binding"`
}

type CanonicalPayment struct {
	ResourceBindingID  string `json:"resource_binding_id"`
	Payer              string `json:"payer"`
	Network            string `json:"network"`
	Asset              string `json:"asset"`
	Receiver           string `json:"receiver"`
	Amount             string `json:"amount"`
	ServiceID          string `json:"service_id"`
	ConfigVersion      int    `json:"config_version"`
	RequestBindingHash string `json:"request_binding_hash"`
	PaymentContextJTI  string `json:"payment_context_jti"`
}

type PaymentContext struct {
	PaymentContextToken string           `json:"payment_context_token"`
	ContextExpiresAt    time.Time        `json:"context_expires_at"`
	CanonicalPayment    CanonicalPayment `json:"canonical_payment"`
}

// CreatePaymentContext handles AgentPay's current {data,request_id} envelope.
// It is a public preflight call and does not grant payment authority.
func (c *RuntimeClient) CreatePaymentContext(ctx context.Context, in PaymentContextRequest) (PaymentContext, error) {
	var out PaymentContext
	if c == nil || c.agentPayURL == "" {
		return out, errors.New("agentauth: AgentPay URL required")
	}
	var envelope struct {
		Data PaymentContext `json:"data"`
	}
	if err := c.call(ctx, c.agentPayURL, "", http.MethodPost, "auth-payment-contexts", "", in, "", &envelope, http.StatusOK); err != nil {
		return out, err
	}
	out = envelope.Data
	if out.PaymentContextToken == "" || out.ContextExpiresAt.IsZero() {
		return out, errors.New("agentauth: invalid AgentPay Context response")
	}
	return out, nil
}

type PaymentExecution struct {
	PaymentExecutionID string           `json:"payment_execution_id"`
	AuthorizationID    string           `json:"authorization_id"`
	Status             string           `json:"status"`
	ClaimReceipt       string           `json:"claim_receipt"`
	SignUntil          time.Time        `json:"sign_until"`
	CanonicalPayment   CanonicalPayment `json:"canonical_payment"`
	SigningPayload     json.RawMessage  `json:"signing_payload"`
	Replayed           bool             `json:"replayed"`
}

func (c *RuntimeClient) PreparePaymentExecution(ctx context.Context, proof, contextToken, businessKey string) (PaymentExecution, error) {
	var out PaymentExecution
	if c == nil || c.agentPayURL == "" {
		return out, errors.New("agentauth: AgentPay URL required")
	}
	if proof == "" || contextToken == "" {
		return out, errors.New("agentauth: proof and original payment Context required")
	}
	if err := validateKey(businessKey); err != nil {
		return out, err
	}
	body := struct {
		AuthorizationProof  string `json:"authorization_proof"`
		PaymentContextToken string `json:"payment_context_token"`
	}{proof, contextToken}
	err := c.callWithSafeRetry(ctx, c.agentPayURL, "agentpay", "auth-payment-executions", businessKey, body, &out, http.StatusCreated, http.StatusOK)
	if err == nil && (out.PaymentExecutionID == "" || out.AuthorizationID == "" || out.ClaimReceipt == "") {
		err = errors.New("agentauth: invalid AgentPay execution response")
	}
	return out, err
}

type PaymentExecutionStatus struct {
	PaymentExecutionID string     `json:"payment_execution_id"`
	AuthorizationID    string     `json:"authorization_id"`
	Status             string     `json:"status"`
	PaymentOrderID     *string    `json:"payment_order_id"`
	TxHash             *string    `json:"tx_hash"`
	ReasonCode         *string    `json:"reason_code"`
	SignUntil          *time.Time `json:"sign_until"`
	UpdatedAt          time.Time  `json:"updated_at"`
}

func (c *RuntimeClient) GetPaymentExecution(ctx context.Context, executionID, originalReceipt string) (PaymentExecutionStatus, error) {
	var out PaymentExecutionStatus
	if c == nil || c.agentPayURL == "" {
		return out, errors.New("agentauth: AgentPay URL required")
	}
	if !validID(executionID, "pex_") || originalReceipt == "" {
		return out, errors.New("agentauth: execution ID and original Receipt required")
	}
	err := c.call(ctx, c.agentPayURL, "agentpay", http.MethodGet, "auth-payment-executions/"+executionID, "", nil, originalReceipt, &out, http.StatusOK)
	if err == nil && out.PaymentExecutionID != executionID {
		err = errors.New("agentauth: execution response ID mismatch")
	}
	return out, err
}

func (c *RuntimeClient) call(ctx context.Context, baseURL, audience, method, path, key string, body any, receipt string, out any, success ...int) error {
	if c == nil {
		return errors.New("agentauth: nil RuntimeClient")
	}
	target, err := url.JoinPath(baseURL, "v1", path)
	if err != nil {
		return err
	}
	var payload []byte
	if body != nil {
		payload, err = json.Marshal(body)
		if err != nil {
			return err
		}
		if len(payload) > 64<<10 {
			return errors.New("agentauth: request too large")
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if receipt != "" {
		req.Header.Set("X-AgentAuth-Claim-Receipt", receipt)
	}
	if audience != "" {
		if err := c.signer.Sign(req, audience, key); err != nil {
			return err
		}
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("agentauth: runtime request: %w", err)
	}
	defer resp.Body.Close()
	raw, err := readLimited(resp.Body, maxResponseBytes)
	if err != nil {
		return err
	}
	for _, status := range success {
		if resp.StatusCode == status {
			return json.Unmarshal(raw, out)
		}
	}
	if audience == "" {
		var wrapped struct {
			Error struct {
				Code      string `json:"code"`
				Message   string `json:"message"`
				Retryable bool   `json:"retryable"`
			} `json:"error"`
			RequestID string `json:"request_id"`
		}
		if json.Unmarshal(raw, &wrapped) == nil && wrapped.Error.Code != "" {
			return &APIError{StatusCode: resp.StatusCode, Code: wrapped.Error.Code, Message: wrapped.Error.Message, Retryable: wrapped.Error.Retryable, RequestID: wrapped.RequestID}
		}
	}
	apiErr := &APIError{StatusCode: resp.StatusCode}
	if json.Unmarshal(raw, apiErr) == nil && apiErr.Code != "" {
		return apiErr
	}
	return fmt.Errorf("agentauth: HTTP %d: invalid error response", resp.StatusCode)
}

// callWithSafeRetry repeats only transient failures. Each attempt sends the
// same business body/key and receives a new signed request envelope.
func (c *RuntimeClient) callWithSafeRetry(ctx context.Context, baseURL, audience, path, key string, body, out any, success ...int) error {
	for attempt := 0; attempt < c.retryAttempts; attempt++ {
		err := c.call(ctx, baseURL, audience, http.MethodPost, path, key, body, "", out, success...)
		if err == nil || !retryableRuntimeError(err) || attempt+1 == c.retryAttempts {
			return err
		}
		timer := time.NewTimer(time.Duration(attempt+1) * 100 * time.Millisecond)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return ctx.Err()
		case <-timer.C:
		}
	}
	return errors.New("agentauth: retry loop exhausted")
}

func retryableRuntimeError(err error) bool {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.Retryable && apiErr.StatusCode >= 500
	}
	var transportErr *url.Error
	return errors.As(err, &transportErr)
}

func readLimited(r io.Reader, max int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, errors.New("agentauth: body too large")
	}
	return b, nil
}
