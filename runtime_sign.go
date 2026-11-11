package agentauth

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
)

// RuntimeSigner holds only the Runtime credential. Keep its private key in the
// Runtime's secret store; never send it to AgentAuth or a Controller backend.
type RuntimeSigner struct {
	sessionID  string
	privateKey ed25519.PrivateKey
	clock      func() time.Time
}

func GenerateRuntimeKey() (ed25519.PrivateKey, error) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	return key, err
}

// RuntimePublicCredential can be sent to a trusted backend before the Session
// exists. The private key stays with the Runtime.
func RuntimePublicCredential(key ed25519.PrivateKey) (RuntimeCredential, error) {
	if len(key) != ed25519.PrivateKeySize || !bytes.Equal(ed25519.NewKeyFromSeed(key.Seed()), key) {
		return RuntimeCredential{}, errors.New("agentauth: Ed25519 private key required")
	}
	return RuntimeCredential{Algorithm: "Ed25519", PublicKey: base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))}, nil
}

func NewRuntimeSigner(sessionID string, key ed25519.PrivateKey) (*RuntimeSigner, error) {
	if !validID(sessionID, "ses_") {
		return nil, errors.New("agentauth: valid Session ID and Ed25519 private key required")
	}
	if _, err := RuntimePublicCredential(key); err != nil {
		return nil, err
	}
	copyKey := append(ed25519.PrivateKey(nil), key...)
	return &RuntimeSigner{sessionID: sessionID, privateKey: copyKey, clock: time.Now}, nil
}

func (s *RuntimeSigner) PublicCredential() RuntimeCredential {
	if s == nil {
		return RuntimeCredential{}
	}
	credential, _ := RuntimePublicCredential(s.privateKey)
	return credential
}

// Sign signs the actual request URL and JSON body. Re-sign every retry with a
// fresh nonce and timestamp, while preserving the business key and body.
func (s *RuntimeSigner) Sign(req *http.Request, audience, businessKey string) error {
	if s == nil || req == nil || req.URL == nil {
		return errors.New("agentauth: runtime signer and request required")
	}
	if audience != "auth" && audience != "agentpay" && audience != "wallet" {
		return errors.New("agentauth: unsupported audience")
	}
	if req.Header.Get("X-Controller-Key") != "" || req.Header.Get("Authorization") != "" || req.Header.Get("X-Internal-Admin-Token") != "" {
		return errors.New("agentauth: mixed credentials are forbidden")
	}
	if req.Method != http.MethodGet {
		if err := validateKey(businessKey); err != nil {
			return err
		}
	} else if businessKey != "" {
		return errors.New("agentauth: GET business key must be empty")
	}
	var body []byte
	if req.GetBody != nil {
		r, err := req.GetBody()
		if err != nil {
			return err
		}
		defer r.Close()
		body, err = readLimited(r, 64<<10)
		if err != nil {
			return err
		}
	} else if req.Body != nil {
		return errors.New("agentauth: request body must be replayable")
	}
	if req.Method == http.MethodGet && len(body) != 0 {
		return errors.New("agentauth: GET must have no body")
	}
	if len(body) == 0 {
		body = []byte("{}")
	}
	canonical, err := canonicalJSON(body)
	if err != nil {
		return err
	}
	bodyHash := sha256.Sum256(canonical)
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	issued := s.clock().UTC().Unix()
	expires := issued + 300
	issuedText, expiresText := strconv.FormatInt(issued, 10), strconv.FormatInt(expires, 10)
	nonceText := base64.RawURLEncoding.EncodeToString(nonce[:])
	message := strings.Join([]string{"agentauth-request-v1", audience, strings.ToUpper(req.Method), canonicalPathAndQuery(req.URL), hex.EncodeToString(bodyHash[:]), businessKey, s.sessionID, issuedText, expiresText, nonceText}, "\n")
	signature := ed25519.Sign(s.privateKey, []byte(message))
	req.Header.Set("X-Session-ID", s.sessionID)
	req.Header.Set("X-Request-Issued-At", issuedText)
	req.Header.Set("X-Request-Expires-At", expiresText)
	req.Header.Set("X-Request-Nonce", nonceText)
	req.Header.Set("X-Request-Signature", base64.RawURLEncoding.EncodeToString(signature))
	if businessKey != "" {
		req.Header.Set("Idempotency-Key", businessKey)
	} else {
		req.Header.Del("Idempotency-Key")
	}
	return nil
}

func validID(id, prefix string) bool {
	if !strings.HasPrefix(id, prefix) || len(id) <= len(prefix) {
		return false
	}
	for _, c := range id {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

func canonicalPathAndQuery(u *url.URL) string {
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	if u.RawQuery == "" {
		return path
	}
	parts := make([]string, 0)
	for _, pair := range strings.Split(u.RawQuery, "&") {
		if pair == "" {
			continue
		}
		k, v, _ := strings.Cut(pair, "=")
		kd, e1 := url.PathUnescape(k)
		vd, e2 := url.PathUnescape(v)
		if e1 != nil {
			kd = k
		}
		if e2 != nil {
			vd = v
		}
		parts = append(parts, encodeRFC3986(kd)+"="+encodeRFC3986(vd))
	}
	sort.Strings(parts)
	return path + "?" + strings.Join(parts, "&")
}

func encodeRFC3986(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("-._~", rune(c)) {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// canonicalJSON covers the I-JSON subset used by V1 payment requests. Values
// with fractional/exponent numbers are rejected to prevent silent hash drift.
func canonicalJSON(raw []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, errors.New("agentauth: trailing or invalid JSON value")
	}
	var b bytes.Buffer
	if err := writeCanonical(&b, v); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func writeCanonical(b *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if x {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case string:
		writeJSONString(b, x)
	case json.Number:
		s := string(x)
		if strings.ContainsAny(s, ".eE") {
			return errors.New("agentauth: fractional/exponent JSON numbers are unsupported in signed payment requests")
		}
		if _, err := strconv.ParseInt(s, 10, 64); err != nil {
			return errors.New("agentauth: signed JSON integer out of range")
		}
		b.WriteString(s)
	case []any:
		b.WriteByte('[')
		for i, item := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := writeCanonical(b, item); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool {
			a, c := utf16.Encode([]rune(keys[i])), utf16.Encode([]rune(keys[j]))
			for n := 0; n < len(a) && n < len(c); n++ {
				if a[n] != c[n] {
					return a[n] < c[n]
				}
			}
			return len(a) < len(c)
		})
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			writeJSONString(b, k)
			b.WriteByte(':')
			if err := writeCanonical(b, x[k]); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	default:
		return fmt.Errorf("agentauth: unsupported JSON value %T", v)
	}
	return nil
}

func writeJSONString(b *bytes.Buffer, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"', '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(b, "\\u%04x", r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
}
