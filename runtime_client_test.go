package agentauth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestRuntimeSignatureAndRetry(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	signer, err := NewRuntimeSigner("ses_test", key)
	if err != nil {
		t.Fatal(err)
	}
	var nonces []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Controller-Key") != "" || r.Header.Get("Idempotency-Key") != "business-1" || r.Header.Get("X-Session-ID") != "ses_test" {
			t.Errorf("wrong credentials or key")
		}
		body, _ := readLimited(r.Body, 64<<10)
		canonical, err := canonicalJSON(body)
		if err != nil {
			t.Error(err)
			return
		}
		hash := sha256.Sum256(canonical)
		msg := strings.Join([]string{"agentauth-request-v1", "auth", "POST", "/v1/authorizations:authorize", hex.EncodeToString(hash[:]), "business-1", "ses_test", r.Header.Get("X-Request-Issued-At"), r.Header.Get("X-Request-Expires-At"), r.Header.Get("X-Request-Nonce")}, "\n")
		sig, _ := base64.RawURLEncoding.DecodeString(r.Header.Get("X-Request-Signature"))
		if !ed25519.Verify(key.Public().(ed25519.PublicKey), []byte(msg), sig) {
			t.Error("invalid runtime signature")
		}
		nonces = append(nonces, r.Header.Get("X-Request-Nonce"))
		if len(nonces) == 1 {
			fmt.Fprint(w, `{"decision":"ALLOW","authorization_id":"aat_1","authorization_proof":"proof","replayed":false}`)
		} else {
			fmt.Fprint(w, `{"authorization_id":"aat_1","status":"CLAIMED","execution_id":"ape_1","replayed":true}`)
		}
	}))
	defer server.Close()
	client, err := NewRuntimeClient(RuntimeConfig{AuthURL: server.URL, Signer: signer})
	if err != nil {
		t.Fatal(err)
	}
	first, err := client.AuthorizePayment(context.Background(), "context", "business-1")
	if err != nil || !first.IsAllowed() {
		t.Fatalf("first: %+v %v", first, err)
	}
	second, err := client.AuthorizePayment(context.Background(), "context", "business-1")
	if err != nil || !second.IsStatusReplay() || second.AuthorizationProof != "" {
		t.Fatalf("replay: %+v %v", second, err)
	}
	if len(nonces) != 2 || nonces[0] == nonces[1] {
		t.Fatal("retry did not get a fresh signed envelope")
	}
}

func TestAgentPayCurrentContextEnvelopeAndExecution(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, ed25519.SeedSize))
	signer, _ := NewRuntimeSigner("ses_test", key)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth-payment-contexts":
			if r.Header.Get("X-Request-Signature") != "" {
				t.Error("public Context request unexpectedly signed")
			}
			fmt.Fprint(w, `{"data":{"payment_context_token":"ctx","context_expires_at":"2026-11-10T10:00:00Z","canonical_payment":{"resource_binding_id":"arb_test"}},"request_id":"req_1"}`)
		case "/v1/auth-payment-executions":
			if r.Header.Get("X-Request-Signature") == "" || r.Header.Get("Idempotency-Key") != "business-1" {
				t.Error("missing signed execution credentials")
			}
			w.WriteHeader(http.StatusCreated)
			fmt.Fprint(w, `{"payment_execution_id":"ape_test","authorization_id":"aat_test","status":"CLAIMED","claim_receipt":"receipt"}`)
		case "/v1/auth-payment-executions/ape_test":
			if r.Header.Get("X-AgentAuth-Claim-Receipt") != "receipt" || r.Header.Get("Idempotency-Key") != "" {
				t.Error("query headers wrong")
			}
			fmt.Fprint(w, `{"payment_execution_id":"ape_test","authorization_id":"aat_test","status":"CLAIMED"}`)
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	client, err := NewRuntimeClient(RuntimeConfig{AuthURL: server.URL, AgentPayURL: server.URL, Signer: signer})
	if err != nil {
		t.Fatal(err)
	}
	ctx, err := client.CreatePaymentContext(context.Background(), PaymentContextRequest{ResourceBindingID: "arb_test", ServiceID: "svc", ConfigVersion: 1, PaymentRequired: json.RawMessage(`{}`), RequestBinding: RequestBinding{Method: "GET", ResourceURL: "https://example.com", RequestHash: strings.Repeat("a", 64), RequestHashVersion: "agentpay-request-v1"}})
	if err != nil || ctx.PaymentContextToken != "ctx" {
		t.Fatalf("Context: %+v %v", ctx, err)
	}
	exec, err := client.PreparePaymentExecution(context.Background(), "proof", ctx.PaymentContextToken, "business-1")
	if err != nil || exec.ClaimReceipt != "receipt" {
		t.Fatalf("Prepare: %+v %v", exec, err)
	}
	status, err := client.GetPaymentExecution(context.Background(), exec.PaymentExecutionID, exec.ClaimReceipt)
	if err != nil || status.Status != "CLAIMED" {
		t.Fatalf("Query: %+v %v", status, err)
	}
	if _, err := client.GetPaymentExecution(context.Background(), "pex_test", exec.ClaimReceipt); err == nil {
		t.Fatal("accepted legacy pex_ payment execution ID")
	}
}

func TestSignedJSONAndCredentialIsolation(t *testing.T) {
	canonical, err := canonicalJSON([]byte(`{"z":"<>&","a":1}`))
	if err != nil || string(canonical) != `{"a":1,"z":"<>&"}` {
		t.Fatalf("JCS: %s %v", canonical, err)
	}
	if _, err := canonicalJSON([]byte(`{} garbage`)); err == nil {
		t.Fatal("accepted trailing JSON")
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, ed25519.SeedSize))
	public, err := RuntimePublicCredential(key)
	if err != nil || public.Algorithm != "Ed25519" || public.PublicKey == "" {
		t.Fatalf("public credential: %+v %v", public, err)
	}
	badKey := append(ed25519.PrivateKey(nil), key...)
	badKey[len(badKey)-1] ^= 1
	if _, err := RuntimePublicCredential(badKey); err == nil {
		t.Fatal("accepted inconsistent private/public key")
	}
	signer, _ := NewRuntimeSigner("ses_test", key)
	req, _ := http.NewRequest(http.MethodPost, "https://auth.example/v1/authorizations:authorize", strings.NewReader(`{}`))
	req.Header.Set("X-Controller-Key", "secret")
	if err := signer.Sign(req, "auth", "op"); err == nil {
		t.Fatal("accepted mixed credentials")
	}
	req.Header.Del("X-Controller-Key")
	if err := signer.Sign(req, "auth", "op"); err != nil {
		t.Fatal(err)
	}
	if req.Header.Get("X-Request-Expires-At") == "" {
		t.Fatal("missing expiry")
	}
}

func TestCanonicalRuntimeQueryMatchesServerVector(t *testing.T) {
	u, _ := url.Parse("/v1/executions/x?z=hello+world&b=%2f&a=2&a=1")
	if got := canonicalPathAndQuery(u); got != "/v1/executions/x?a=1&a=2&b=%2F&z=hello%2Bworld" {
		t.Fatalf("query canonicalization drift: %s", got)
	}
}

func TestAuthorizeTransientRetryKeepsBusinessKey(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{4}, ed25519.SeedSize))
	signer, _ := NewRuntimeSigner("ses_test", key)
	var keys, nonces []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		keys = append(keys, r.Header.Get("Idempotency-Key"))
		nonces = append(nonces, r.Header.Get("X-Request-Nonce"))
		if len(keys) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprint(w, `{"error_code":"DEPENDENCY_UNAVAILABLE","retryable":true}`)
			return
		}
		fmt.Fprint(w, `{"decision":"ALLOW","authorization_id":"aat_test","authorization_proof":"proof"}`)
	}))
	defer server.Close()
	client, err := NewRuntimeClient(RuntimeConfig{AuthURL: server.URL, Signer: signer})
	if err != nil {
		t.Fatal(err)
	}
	out, err := client.AuthorizePayment(context.Background(), "original-context", "business-1")
	if err != nil || !out.IsAllowed() {
		t.Fatalf("retry: %+v %v", out, err)
	}
	if len(keys) != 2 || keys[0] != keys[1] || nonces[0] == nonces[1] {
		t.Fatalf("retry keys/nonces: %v %v", keys, nonces)
	}
}
