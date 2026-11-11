package agentauth

import (
	"context"
	"errors"
	"net/http"
	"time"
)

// ProtectionEnableOperation is a durable platform operation. IntegrationStatus is the current
// cross-service snapshot; Status describes the operation's last processing result.
type ProtectionEnableOperation struct {
	OperationID       string             `json:"operation_id"`
	ProjectID         string             `json:"project_id"`
	SessionID         string             `json:"session_id"`
	ResourceBindingID string             `json:"resource_binding_id"`
	AuthAgentID       string             `json:"auth_agent_id"`
	Status            string             `json:"status"`
	ReasonCode        string             `json:"reason_code,omitempty"`
	AttemptCount      int                `json:"attempt_count"`
	CreatedAt         time.Time          `json:"created_at"`
	UpdatedAt         time.Time          `json:"updated_at"`
	CompletedAt       *time.Time         `json:"completed_at,omitempty"`
	Replayed          bool               `json:"replayed"`
	IntegrationStatus *IntegrationStatus `json:"integration_status,omitempty"`
}

// EnablePaymentProtection must be called by a trusted backend after it verifies the local
// Agent manager and records the authorized person's explicit confirmation of approvedDigest.
// Retry an uncertain response with the same key, digest and confirmation reference.
func (c *ControllerClient) EnablePaymentProtection(ctx context.Context, sessionID, approvedDigest, confirmationRef, key string) (ProtectionEnableOperation, error) {
	var out ProtectionEnableOperation
	if !validID(sessionID, "ses_") || len(approvedDigest) != 64 || confirmationRef == "" {
		return out, errors.New("agentauth: Session ID, policy digest and confirmation reference required")
	}
	err := c.call(ctx, http.MethodPost, "sessions/"+sessionID+"/payment-protection:enable", key, struct {
		PolicyDigest    string `json:"policy_digest"`
		ConfirmationRef string `json:"confirmation_ref"`
	}{approvedDigest, confirmationRef}, &out, http.StatusAccepted)
	if err == nil && (out.SessionID != sessionID || out.ProjectID != c.projectID || out.OperationID == "") {
		err = errors.New("agentauth: enable operation response violates project or session contract")
	}
	return out, err
}

func (c *ControllerClient) GetPaymentProtectionOperation(ctx context.Context, id string) (ProtectionEnableOperation, error) {
	var out ProtectionEnableOperation
	if !validID(id, "ape_") {
		return out, errors.New("agentauth: invalid protection enable operation ID")
	}
	err := c.call(ctx, http.MethodGet, "payment-protection-operations/"+id, "", nil, &out, http.StatusOK)
	if err == nil && (out.OperationID != id || out.ProjectID != c.projectID) {
		err = errors.New("agentauth: enable operation response violates project contract")
	}
	return out, err
}
