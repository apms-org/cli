package apm

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func newUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

var guidRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// DecodeFlexibleBase64 accepts standard or URL-safe base64, padded or not.
func DecodeFlexibleBase64(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimRight(s, "=")
	s = strings.NewReplacer("+", "-", "/", "_", "\n", "", "\r", "", " ", "").Replace(s)
	return base64.RawURLEncoding.DecodeString(s)
}

// CredentialIDBytes decodes a passkey credential ID from any encoding the
// supported formats use: base64url, base64, a Bitwarden GUID or "b64." prefix.
func CredentialIDBytes(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("empty credential ID")
	}
	if strings.HasPrefix(s, "b64.") {
		return DecodeFlexibleBase64(s[4:])
	}
	if guidRe.MatchString(s) {
		return hex.DecodeString(strings.ReplaceAll(s, "-", ""))
	}
	return DecodeFlexibleBase64(s)
}

func NormalizePasskeyCredentialID(s string) string {
	b, err := CredentialIDBytes(s)
	if err != nil || len(b) == 0 {
		return strings.TrimRight(strings.NewReplacer("+", "-", "/", "_").Replace(strings.TrimSpace(s)), "=")
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// BitwardenCredentialID writes a credential ID the way Bitwarden stores it: a
// GUID for 16-byte IDs and "b64." plus base64url for everything else.
func BitwardenCredentialID(s string) string {
	b, err := CredentialIDBytes(s)
	if err != nil {
		return s
	}
	if len(b) == 16 {
		h := hex.EncodeToString(b)
		return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
	}
	return "b64." + base64.RawURLEncoding.EncodeToString(b)
}

type passkeyJWKData struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	D   string `json:"d,omitempty"`
}

func pad32(b []byte) []byte {
	if len(b) >= 32 {
		return b
	}
	return append(make([]byte, 32-len(b)), b...)
}

func jwkFromECDSA(priv *ecdsa.PrivateKey) (json.RawMessage, error) {
	if priv.Curve != elliptic.P256() {
		return nil, errors.New("only P-256 keys are supported")
	}
	pub, err := priv.PublicKey.Bytes()
	if err != nil {
		return nil, err
	}
	d, err := priv.Bytes()
	if err != nil {
		return nil, err
	}
	enc := base64.RawURLEncoding.EncodeToString
	return json.Marshal(passkeyJWKData{Kty: "EC", Crv: "P-256", X: enc(pub[1:33]), Y: enc(pub[33:65]), D: enc(d)})
}

// PasskeyKeyFromPKCS8 turns a PKCS#8 private key (what Bitwarden and the
// Credential Exchange Format carry) into the JWK APM stores. APM signs with
// ES256, so only P-256 ECDSA keys are accepted.
func PasskeyKeyFromPKCS8(der []byte) (json.RawMessage, error) {
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		if ec, ecErr := x509.ParseECPrivateKey(der); ecErr == nil {
			return jwkFromECDSA(ec)
		}
		return nil, fmt.Errorf("the private key is not readable PKCS#8")
	}
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		if k.Curve != elliptic.P256() {
			return nil, fmt.Errorf("the key uses %s; APM passkeys use P-256", k.Curve.Params().Name)
		}
		return jwkFromECDSA(k)
	default:
		return nil, fmt.Errorf("the key is %T; APM passkeys use ES256 (P-256)", key)
	}
}

// PasskeyKeyFromPEM reads a PEM private key, as KeePassXC stores passkeys.
func PasskeyKeyFromPEM(text string) (json.RawMessage, error) {
	block, _ := pem.Decode([]byte(strings.TrimSpace(text)))
	if block == nil {
		return nil, errors.New("the private key is not PEM")
	}
	return PasskeyKeyFromPKCS8(block.Bytes)
}

func passkeyECDSA(raw json.RawMessage) (*ecdsa.PrivateKey, error) {
	var jwk passkeyJWKData
	if err := json.Unmarshal(raw, &jwk); err != nil {
		var wrapped string
		if json.Unmarshal(raw, &wrapped) != nil || json.Unmarshal([]byte(wrapped), &jwk) != nil {
			return nil, errors.New("the stored key is not a JWK")
		}
	}
	d, err := DecodeFlexibleBase64(jwk.D)
	if err != nil || len(d) == 0 || len(d) > 32 {
		return nil, errors.New("the stored key has no private part")
	}
	return ecdsa.ParseRawPrivateKey(elliptic.P256(), pad32(d))
}

// PasskeyPKCS8 returns the passkey's private key as PKCS#8 DER for export.
func PasskeyPKCS8(p Passkey) ([]byte, error) {
	priv, err := passkeyECDSA(p.PrivateKey)
	if err != nil {
		return nil, err
	}
	return x509.MarshalPKCS8PrivateKey(priv)
}

func PasskeyPEM(p Passkey) (string, error) {
	der, err := PasskeyPKCS8(p)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), nil
}

type ImportedPasskey struct {
	RPID            string
	UserName        string
	UserDisplayName string
	UserHandle      string
	CredentialID    string
	Key             json.RawMessage
	SignCount       int64
	Created         time.Time
}

// NewPasskey builds a passkey in the shape the extension bridge signs with:
// base64url credential ID and user handle, JWK private key, JS timestamp.
func NewPasskey(in ImportedPasskey) (Passkey, error) {
	rp := strings.ToLower(strings.TrimSpace(in.RPID))
	if rp == "" {
		return Passkey{}, errors.New("it has no website (rpId)")
	}
	cred := NormalizePasskeyCredentialID(in.CredentialID)
	if cred == "" {
		return Passkey{}, errors.New("it has no credential ID")
	}
	if len(in.Key) == 0 {
		return Passkey{}, errors.New("the export does not include its private key")
	}
	if _, err := passkeyECDSA(in.Key); err != nil {
		return Passkey{}, err
	}
	handle := ""
	if strings.TrimSpace(in.UserHandle) != "" {
		b, err := DecodeFlexibleBase64(in.UserHandle)
		if err != nil {
			b = []byte(in.UserHandle)
		}
		handle = base64.RawURLEncoding.EncodeToString(b)
	}
	created := in.Created
	if created.IsZero() {
		created = time.Now()
	}
	display := strings.TrimSpace(in.UserDisplayName)
	if display == "" {
		display = strings.TrimSpace(in.UserName)
	}
	return Passkey{
		ID:              newUUID(),
		RPID:            rp,
		UserName:        strings.TrimSpace(in.UserName),
		UserDisplayName: display,
		UserHandle:      handle,
		CredentialID:    cred,
		PrivateKey:      in.Key,
		SignCount:       in.SignCount,
		CreatedAt:       created.UTC().Format("2006-01-02T15:04:05.000Z"),
	}, nil
}

// AddPasskey validates a passkey from an export and attaches it to the item,
// or records why it could not come along.
func (it *TransferItem) AddPasskey(in ImportedPasskey) {
	pk, err := NewPasskey(in)
	if err != nil {
		it.DropPasskey(in.RPID, in.UserName, strings.ToUpper(err.Error()[:1])+err.Error()[1:])
		return
	}
	for _, have := range it.Passkeys {
		if have.CredentialID == pk.CredentialID {
			return
		}
	}
	it.Passkeys = append(it.Passkeys, pk)
}

func PasskeyCreated(p Passkey) time.Time {
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05.000Z"} {
		if t, err := time.Parse(layout, p.CreatedAt); err == nil {
			return t
		}
	}
	return time.Time{}
}

func ParseTransferTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05.000Z", "2006-01-02 15:04:05", "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		if n > 1e12 {
			return time.UnixMilli(n)
		}
		return time.Unix(n, 0)
	}
	return time.Time{}
}

// One-time codes

type OTPAuth struct {
	Type      string
	Label     string
	Issuer    string
	Account   string
	Secret    string
	Digits    int
	Period    int
	Algorithm string
}

func ParseOTPAuth(raw string) (OTPAuth, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || !strings.EqualFold(u.Scheme, "otpauth") {
		return OTPAuth{}, errors.New("not an otpauth:// link")
	}
	o := OTPAuth{Type: strings.ToLower(u.Host), Digits: 6, Period: 30, Algorithm: "SHA1"}
	label, _ := url.PathUnescape(strings.TrimPrefix(u.Path, "/"))
	o.Label = label
	q := u.Query()
	o.Secret = q.Get("secret")
	o.Issuer = q.Get("issuer")
	if i := strings.Index(label, ":"); i >= 0 {
		if o.Issuer == "" {
			o.Issuer = strings.TrimSpace(label[:i])
		}
		o.Account = strings.TrimSpace(label[i+1:])
	} else {
		o.Account = strings.TrimSpace(label)
	}
	if d := q.Get("digits"); d != "" {
		o.Digits, _ = strconv.Atoi(d)
	}
	if p := q.Get("period"); p != "" {
		o.Period, _ = strconv.Atoi(p)
	}
	if a := q.Get("algorithm"); a != "" {
		o.Algorithm = strings.ToUpper(a)
	}
	return o, nil
}

// Name for an authenticator item: "Issuer (account)" or whichever exists.
func (o OTPAuth) Name() string {
	switch {
	case o.Issuer != "" && o.Account != "" && !strings.EqualFold(o.Issuer, o.Account):
		return o.Issuer + " (" + o.Account + ")"
	case o.Issuer != "":
		return o.Issuer
	}
	return o.Account
}

func normalizeTOTPSecret(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	s = strings.NewReplacer(" ", "", "-", "", "\t", "").Replace(s)
	return strings.TrimRight(s, "=")
}

// TOTPSecretFrom takes a raw setup key or an otpauth:// link and returns the
// key APM stores, or a reason APM cannot generate its codes.
func TOTPSecretFrom(raw string) (string, string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", ""
	}
	lower := strings.ToLower(raw)
	if strings.HasPrefix(lower, "steam://") {
		return "", "Steam Guard codes are not supported. APM generates standard 6-digit codes"
	}
	secret := raw
	if strings.HasPrefix(lower, "otpauth://") {
		o, err := ParseOTPAuth(raw)
		if err != nil {
			return "", "The otpauth:// link is not valid"
		}
		if o.Type == "hotp" {
			return "", "Counter-based (HOTP) codes are not supported. APM generates time-based codes"
		}
		if o.Digits != 0 && o.Digits != 6 {
			return "", fmt.Sprintf("It uses %d-digit codes. APM generates 6-digit codes", o.Digits)
		}
		if o.Period != 0 && o.Period != 30 {
			return "", fmt.Sprintf("Its codes change every %ds. APM generates 30s codes", o.Period)
		}
		if o.Algorithm != "" && o.Algorithm != "SHA1" {
			return "", fmt.Sprintf("It uses %s. APM generates SHA-1 codes", o.Algorithm)
		}
		secret = o.Secret
	}
	secret = normalizeTOTPSecret(secret)
	if secret == "" {
		return "", "It has no setup key"
	}
	padded := secret
	if n := len(padded) % 8; n != 0 {
		padded += strings.Repeat("=", 8-n)
	}
	if _, err := base32.StdEncoding.DecodeString(padded); err != nil {
		return secret, "The setup key is not valid base32"
	}
	return secret, ""
}

func HostOf(raw string) string { return normalizeDomain(raw) }
