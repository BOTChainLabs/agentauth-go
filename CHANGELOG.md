# Changelog

## v0.1.0

Initial public release of the AgentAuth Go SDK.

- Trusted-backend client for Agent association recovery, resource bindings, Sessions, integration status, and payment protection enablement.
- Runtime Ed25519 request signing and clients for AgentAuth authorization and AgentPay payment Context and execution APIs.
- Safe retry and status-query helpers for uncertain Runtime outcomes.

Compatibility: AgentAuth `/v1` control and Runtime payment APIs described in `AgentAuth_技术实施说明.md` v1.5, and the corresponding AgentPay Auth Context and payment execution `/v1` APIs. The SDK supports the `X402_PAYMENT` flow. Live cross-service acceptance with a non-Raise project is tracked separately under T1.4.
