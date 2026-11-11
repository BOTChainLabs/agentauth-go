# AgentAuth Go SDK

AgentAuth client for trusted integration backends and Agent Runtimes. This module is independent of the private `agent-auth-service` Go module. The backend and Runtime use separate client types and credentials.

Install the published release with `go get github.com/BOTChainLabs/agentauth-go@v0.1.0`.

## Register and recover an association

Use this client only in a trusted backend. First verify that the current user may manage the business Agent. Keep the Project Controller Key out of frontends and Agent Runtimes.

```go
client, err := agentauth.NewControllerClient(agentauth.ControllerConfig{
    BaseURL:       "https://auth.example.com",
    ControllerKey: projectControllerKey,
    ProjectID:     "my-project",
})
if err != nil { return err }

association, err := client.RegisterAgent(ctx, agentauth.RegisterAgentRequest{
    ExternalAgentID: existingAgentID,
    Name:            displayName,
    IdempotencyKey:  registrationOperationID,
})
if err != nil { return err }
// Persist association.ProjectID, association.ExternalAgentID, and
// association.AuthAgentID in the caller's own store.
```

If an HTTP outcome is uncertain, retry with the **same body and idempotency key**. If remote registration succeeded but the local association was not saved, use the original Project credential and stable business ID:

```go
association, err := client.RecoverAgent(ctx, existingAgentID, displayName)
```

Recovery may use a newer display name; AgentAuth returns the originally saved name and current status. A paused Agent remains paused. A reused association is not permission to execute: resource binding, Session approval, and payment protection are separate steps. `RecoverAgent` generates a fresh idempotency key; the server's `(project_id, external_agent_id)` uniqueness provides recovery even after the original key is lost or expires.

## Resource and Session control

The trusted backend can call `CreateBindingChallenge`, `CreateBinding`, `GetBinding`, `ListBindings`, and `RevokeBinding`. Pass the challenge's **exact** `Message` to the EOA owner for `personal_sign`, or obtain a Wallet resource-control assertion from Wallet's authorized management API. The SDK does not sign on behalf of an owner. Supply an explicit, stable `IdempotencyKey` on every control-plane write; replay an uncertain outcome with the same request body and key.

Generate the Runtime key on the Runtime and give only `RuntimePublicCredential(key)` to the backend. The backend calls `CreateSession` with that public credential, shows the returned rules and `PolicyDigest` to the authorized person, then calls `ActivateSession` with the approved digest. Only after the backend returns the new Session ID does the Runtime call `NewRuntimeSigner`. Session creation alone leaves it `DRAFT`. `GetIntegrationStatus` is a read-only snapshot; `READY` does not replace execution-time authorization.

After checking the local Agent manager and recording the authorized person's explicit confirmation, the trusted backend may call `EnablePaymentProtection(ctx, sessionID, approvedDigest, confirmationRecordID, stableOperationKey)`. This returns a durable operation; use `GetPaymentProtectionOperation` and its current `IntegrationStatus` to follow progress. A pending or unknown operation is not permission to pay. Repeat an uncertain request with the same key, digest, and confirmation reference. AgentAuth holds the AgentPay Admin credential; the SDK never does. Once the binding, Session and payment service checks pass, the platform enables AgentPay protection without an additional path switch.

## Runtime payment calls

```go
key, err := agentauth.GenerateRuntimeKey() // store securely before creating the Session
if err != nil { return err }
signer, err := agentauth.NewRuntimeSigner(sessionID, key)
if err != nil { return err }
runtime, err := agentauth.NewRuntimeClient(agentauth.RuntimeConfig{
    AuthURL: "https://auth.example.com", AgentPayURL: "https://agentpay.example.com",
    Signer: signer,
})
if err != nil { return err }

// After receiving the Provider's 402 payment_required and request binding:
paymentContext, err := runtime.CreatePaymentContext(ctx, contextRequest)
if err != nil { return err }
decision, err := runtime.AuthorizePayment(ctx, paymentContext.PaymentContextToken, stableBusinessKey)
if err != nil { return err }
if decision.IsDenied() { /* handle decision.ReasonCode */ }
if decision.IsStatusReplay() { /* query the original Authorization/Execution */ }
if decision.IsAllowed() {
    execution, err := runtime.PreparePaymentExecution(ctx, decision.AuthorizationProof,
        paymentContext.PaymentContextToken, stableBusinessKey)
    _ = execution
    if err != nil { return err }
}
```

`AuthorizePayment` and `PreparePaymentExecution` retry transient failures once by default. Each attempt uses the same business key and body with a fresh Runtime signature. Set `RetryAttempts: 1` to disable automatic retries. A changed payment Context, Session, or business action needs a new business key; a 409 conflict is returned to the caller. The SDK never treats a timeout as proof that a payment did not execute. `GetAuthorization` and `GetPaymentExecution` query original outcomes. The EOA Permit2 signature and Wallet payment authorization remain separate resource-owner operations; the Runtime can use `RuntimeSigner.Sign` with the `wallet` audience where the Wallet API requires its signed envelope.

AgentPay currently wraps `POST /v1/auth-payment-contexts` success in `{ "data": ... }`. The SDK handles that response specifically; its execution API uses direct JSON. The AgentPay server response is not changed by this SDK.

If the business system has no Agent ID yet, generate one **and persist it before registration**. Generating a fresh ID on each retry would create separate associations. The SDK does not store business records or decide who may manage an Agent.

For a compilable trusted-backend composition example, see [`examples/controller/flow.go`](examples/controller/flow.go). It calls the SDK methods in enrollment order and exposes callbacks for local Agent ownership checks, association persistence, resource-owner proof, and human policy confirmation. The integrating service must implement these callbacks; the example is not a one-call authorization API. Wallet management calls are outside this module.

The SDK requires the response Project to match `ControllerConfig.ProjectID`. An incorrect Controller Key therefore fails instead of silently associating the Agent under another Project. Inspect API failures with `errors.As(err, &apiErr)` where `apiErr` is `*agentauth.APIError`.

## Development

```bash
go test ./...
go vet ./...
```

API compatibility: AgentAuth `/v1` control and Runtime payment endpoints as specified in `AgentAuth_技术实施说明.md` v1.5 §§2–4, plus the corresponding AgentPay Auth Context and execution `/v1` endpoints. See [CHANGELOG.md](CHANGELOG.md) for release scope and acceptance status.
