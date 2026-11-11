// Package controller shows how a trusted integration backend composes the
// AgentAuth Go SDK with its own identity, persistence, and approval systems.
// It is an example, not an additional SDK entry point.
package controller

import (
	"context"
	"errors"
	"fmt"
	"time"

	agentauth "github.com/BOTChainLabs/agentauth-go"
)

// Proof is supplied by the actual resource controller. Exactly one field is set.
type Proof struct {
	EOASignature             string
	ResourceControlAssertion string
}

// Callbacks are implemented by the integrating backend. The SDK cannot infer
// business Agent ownership or the authorized person's approval.
type Callbacks struct {
	VerifyAgentManager func(context.Context, string) error
	SaveAssociation    func(context.Context, agentauth.AgentAssociation) error
	ProveResource      func(context.Context, agentauth.BindingChallenge) (Proof, error)
	ConfirmPolicy      func(context.Context, agentauth.Session) (confirmationRef string, err error)
}

type Request struct {
	ExternalAgentID   string
	Name              string
	Resource          agentauth.ResourceSpec
	Grant             agentauth.Grant
	GrantLimits       agentauth.Limits
	SessionLimits     agentauth.Limits
	BindingValidUntil time.Time
	SessionValidUntil time.Time
	RuntimeCredential agentauth.RuntimeCredential // public key only; generated in Runtime
	OperationKey      string                      // durable key for this enrollment attempt
}

type Result struct {
	Association agentauth.AgentAssociation
	Binding     agentauth.ResourceBinding
	Session     agentauth.Session
	Operation   agentauth.ProtectionEnableOperation
	Status      agentauth.IntegrationStatus
}

// Enroll runs the control-plane sequence. Each write uses a distinct stable
// key; on an uncertain response, retry the same step with the same body/key.
// A fresh binding challenge is needed if the old one expires before proof.
func Enroll(ctx context.Context, client *agentauth.ControllerClient, callbacks Callbacks, in Request) (Result, error) {
	var out Result
	if client == nil || callbacks.VerifyAgentManager == nil || callbacks.SaveAssociation == nil || callbacks.ProveResource == nil || callbacks.ConfirmPolicy == nil {
		return out, errors.New("controller example: client and all callbacks are required")
	}
	if in.OperationKey == "" || in.RuntimeCredential.Algorithm != "Ed25519" || in.RuntimeCredential.PublicKey == "" {
		return out, errors.New("controller example: durable operation key and Runtime public credential are required")
	}
	if err := callbacks.VerifyAgentManager(ctx, in.ExternalAgentID); err != nil {
		return out, fmt.Errorf("verify local Agent manager: %w", err)
	}
	association, err := client.RegisterAgent(ctx, agentauth.RegisterAgentRequest{
		ExternalAgentID: in.ExternalAgentID, Name: in.Name, IdempotencyKey: in.OperationKey + ":register",
	})
	if err != nil {
		return out, err
	}
	out.Association = association
	if err := callbacks.SaveAssociation(ctx, association); err != nil {
		// RecoverAgent(ctx, externalAgentID, name) can find the same Auth ID later.
		return out, fmt.Errorf("persist Auth association: %w", err)
	}
	if association.Status != "ACTIVE" {
		return out, errors.New("Auth Agent is paused")
	}

	challenge, err := client.CreateBindingChallenge(ctx, association.AuthAgentID, agentauth.BindingChallengeRequest{
		Resource: in.Resource, Grant: in.Grant, GrantLimits: in.GrantLimits,
		ValidUntil: in.BindingValidUntil, IdempotencyKey: in.OperationKey + ":challenge",
	})
	if err != nil {
		return out, err
	}
	proof, err := callbacks.ProveResource(ctx, challenge)
	if err != nil {
		return out, err
	}
	binding, err := client.CreateBinding(ctx, association.AuthAgentID, agentauth.CreateBindingRequest{
		ChallengeToken: challenge.ChallengeToken, Resource: in.Resource, Grant: in.Grant,
		GrantLimits: in.GrantLimits, EOASignature: proof.EOASignature,
		ResourceControlAssertion: proof.ResourceControlAssertion, IdempotencyKey: in.OperationKey + ":binding",
	})
	if err != nil {
		return out, err
	}
	out.Binding = binding

	session, err := client.CreateSession(ctx, association.AuthAgentID, agentauth.CreateSessionRequest{
		ResourceBindingID: binding.ResourceBindingID, RuntimeCredential: in.RuntimeCredential,
		Rules: in.Grant, Limits: in.SessionLimits, ValidUntil: in.SessionValidUntil,
		IdempotencyKey: in.OperationKey + ":session",
	})
	if err != nil {
		return out, err
	}
	out.Session = session
	// The callback must show the policy and PolicyDigest to an authorized person,
	// verify their decision, persist the confirmation, and return its record ID.
	confirmationRef, err := callbacks.ConfirmPolicy(ctx, session)
	if err != nil {
		return out, err
	}
	if confirmationRef == "" {
		return out, errors.New("authorized person's confirmation is required")
	}
	if _, err := client.ActivateSession(ctx, session.SessionID, session.PolicyDigest, in.OperationKey+":activate"); err != nil {
		return out, err
	}
	operation, err := client.EnablePaymentProtection(ctx, session.SessionID, session.PolicyDigest, confirmationRef, in.OperationKey+":enable")
	if err != nil {
		return out, err
	}
	out.Operation = operation
	status, err := client.GetIntegrationStatus(ctx, session.SessionID)
	if err != nil {
		return out, err
	}
	out.Status = status // READY/PENDING/UNKNOWN; never treat operation history as execution permission.
	return out, nil
}
