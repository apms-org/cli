package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
)

func TestBridgeEntropyMatchesGUI(t *testing.T) {
	cases := []struct {
		pw    string
		bits  int
		score int
	}{
		{"Gh-Secret-Pa55word-XYZ", 141, 4},
		{"abc12", 26, 0},
		{"Shared-Reuse-Pass-991", 135, 4},
		{"wifi-secret-violet-71", 124, 4},
		{"Password2024!", 13, 0},
		{"aaaaaaaaaaaa", 45, 2},
		{"Tiger-Maple-Ocean", 25, 0},
		{"Summer2020", 29, 1},
		{"12345678", 9, 0},
		{"correct horse", 73, 3},
		{"Zz9!Zz9!Zz9!", 77, 3},
		{"héllo wörld 😀😀😀", 102, 4},
		{"Coral-Bison-Delta7-Frost", 37, 1},
		{"NewSite-Pass-123!", 109, 4},
		{"", 0, 0},
	}
	for _, c := range cases {
		bits := guiEntropy(c.pw)
		if bits != c.bits || guiScore(bits) != c.score {
			t.Errorf("entropy(%q) = %d score %d, want %d score %d", c.pw, bits, guiScore(bits), c.bits, c.score)
		}
	}
}

func TestBridgeSubRules(t *testing.T) {
	cases := []struct {
		typ  string
		f    map[string]any
		want string
	}{
		{"password", map[string]any{"username": "octo", "website": "github.com"}, "octo"},
		{"password", map[string]any{"username": "", "website": "github.com"}, "github.com"},
		{"totp", map[string]any{"secret": "JBSWY3DPEHPK3PXP"}, "6 digits · 30s"},
		{"note", map[string]any{"content": "first line\nsecond"}, ""},
		{"wifi", map[string]any{"ssid": "Home-5G", "security_type": "WPA3 Personal"}, "Home-5G · WPA3 Personal"},
		{"govid", map[string]any{"type": "Passport", "expiry": "2031-05-01"}, "Passport · expires 2031"},
		{"medical", map[string]any{"insurance_id": "med-1"}, ""},
		{"travel", map[string]any{"ticket_number": "", "loyalty_program": "Miles"}, "Miles"},
		{"contact", map[string]any{"email": "", "phone": "+1 555"}, "+1 555"},
		{"recovery", map[string]any{"codes": []string{"a", "b", "c"}, "used": []string{"a"}}, "3 codes · 2 unused"},
		{"apikey", map[string]any{"service": "Stripe"}, "Stripe"},
		{"token", map[string]any{"type": "PAT"}, "PAT"},
		{"ssh_key", map[string]any{"private_key": "ssh-ED25519 AAAA"}, "ed25519"},
		{"ssh_key", map[string]any{"private_key": "-----BEGIN RSA PRIVATE KEY-----"}, "RSA"},
		{"ssh_key", map[string]any{"private_key": "opaque"}, "Private key"},
		{"ssh_config", map[string]any{"user": "root", "host": "10.0.0.2", "port": "2222"}, "root@10.0.0.2:2222"},
		{"ssh_config", map[string]any{"user": "", "host": "box", "port": "22"}, "box"},
		{"cloud", map[string]any{"region": "", "account_id": "1234"}, "1234"},
		{"k8s", map[string]any{"namespace": "prod", "cluster_url": "https://k"}, "prod · https://k"},
		{"docker", map[string]any{"username": "dock", "registry_url": "registry-1.docker.io"}, "dock · registry-1.docker.io"},
		{"docker", map[string]any{"username": "", "registry_url": "ghcr.io"}, "ghcr.io"},
		{"cicd", map[string]any{"env_vars": "A=1,B=2\nC=3"}, "3 variables"},
		{"cicd", map[string]any{"env_vars": ""}, "Webhook"},
		{"certificate", map[string]any{"issuer": "LE", "expiry": "2027-01-02"}, "LE · expires 2027-01-02"},
		{"banking", map[string]any{"type": "", "details": "4111 1111 1111 1234"}, "Card ···· 1234"},
		{"banking", map[string]any{"type": "IBAN", "details": "123"}, "IBAN"},
		{"license", map[string]any{"activation_info": "seat 1"}, "seat 1"},
		{"legal", map[string]any{"parties_involved": "Me, You"}, "Me, You"},
		{"photo", map[string]any{"file": map[string]any{"name": "scan.png", "size": 35, "mime": "image/png"}}, "scan.png · 35 B"},
		{"document", map[string]any{"file": map[string]any{"name": "a.pdf", "size": 1536, "mime": "application/pdf"}}, "a.pdf · 2 KB"},
		{"video", map[string]any{"file": map[string]any{"name": "v.mp4", "size": 1572864, "mime": "video/mp4"}}, "v.mp4 · 1.5 MB"},
	}
	for _, c := range cases {
		if got := bridgeSub(c.typ, c.f); got != c.want {
			t.Errorf("sub(%s) = %q, want %q", c.typ, got, c.want)
		}
	}
}

func TestBridgeRPCheck(t *testing.T) {
	ok := [][2]string{
		{"https://github.com", "github.com"},
		{"https://login.github.com", "github.com"},
		{"https://github.com:8443", "github.com"},
		{"http://localhost:5173", "localhost"},
		{"http://127.0.0.1:8080", "127.0.0.1"},
		{"https://app.example.co.uk", "example.co.uk"},
	}
	for _, c := range ok {
		if err := bridgeRPCheck(c[0], c[1]); err != nil {
			t.Errorf("rp check %v should pass: %v", c, err)
		}
	}
	bad := [][2]string{
		{"https://evil.com", "github.com"},
		{"https://notgithub.com", "github.com"},
		{"http://github.com", "github.com"},
		{"https://github.com", "com"},
		{"https://foo.co.uk", "co.uk"},
		{"https://github.com/path", "github.com"},
		{"chrome-extension://abc", "abc"},
		{"", "github.com"},
		{"https://github.com", ""},
		{"https://1.2.3.4", "3.4"},
		{"https://user.github.io", "github.io"},
	}
	for _, c := range bad {
		if err := bridgeRPCheck(c[0], c[1]); err == nil {
			t.Errorf("rp check %v should fail", c)
		}
	}
}

func TestBridgeCBOR(t *testing.T) {
	x := bytes.Repeat([]byte{0x11}, 32)
	y := bytes.Repeat([]byte{0x22}, 32)
	cose := coseES256Key(x, y)
	want := "a50102032620012158201111111111111111111111111111111111111111111111111111111111111111225820" + hex.EncodeToString(y)
	if hex.EncodeToString(cose) != want {
		t.Fatalf("COSE key = %x", cose)
	}
	att := noneAttestationObject([]byte{1, 2, 3})
	if hex.EncodeToString(att) != "a363666d74646e6f6e656761747453746d74a06861757468446174614301020"+"3" {
		t.Fatalf("attestation object = %x", att)
	}
	if hex.EncodeToString(cborInt(-7)) != "26" || hex.EncodeToString(cborBytes(make([]byte, 300))[:3]) != "59012c" {
		t.Fatalf("cbor ints or bytes wrong")
	}
}

func TestBridgePasskeyKeyFormats(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	d, _ := priv.Bytes()
	pub, _ := priv.PublicKey.Bytes()
	webcrypto, _ := json.Marshal(map[string]any{"crv": "P-256", "d": b64url(d), "ext": true, "key_ops": []string{"sign"}, "kty": "EC", "x": b64url(pub[1:33]), "y": b64url(pub[33:])})
	wrapped, _ := json.Marshal(string(webcrypto))
	for _, raw := range []json.RawMessage{webcrypto, wrapped} {
		k, err := passkeyPrivateKey(raw)
		if err != nil {
			t.Fatalf("parse %s: %v", raw, err)
		}
		digest := sha256.Sum256([]byte("msg"))
		sig, err := ecdsa.SignASN1(rand.Reader, k, digest[:])
		if err != nil || !ecdsa.VerifyASN1(&priv.PublicKey, digest[:], sig) {
			t.Fatalf("signature from parsed key does not verify")
		}
	}
	for _, raw := range []string{`{"kty":"EC","crv":"P-256","d":"secret"}`, `{"kty":"RSA","d":"AQAB"}`, `null`, `"x"`} {
		if _, err := passkeyPrivateKey(json.RawMessage(raw)); err == nil {
			t.Fatalf("expected an error for %s", raw)
		}
	}
}

func TestBridgeHostAndDomain(t *testing.T) {
	cases := map[string]string{
		"https://www.GitHub.com/login": "github.com",
		"github.com":                   "github.com",
		"user@example.com:8443/x":      "example.com",
		"accounts.google.com.":         "accounts.google.com",
	}
	for in, want := range cases {
		if got := bridgeHost(in); got != want {
			t.Errorf("bridgeHost(%q) = %q, want %q", in, got, want)
		}
	}
	if registrableDomain("accounts.google.com") != "google.com" || registrableDomain("a.b.example.co.uk") != "example.co.uk" || registrableDomain("localhost") != "localhost" {
		t.Fatalf("registrable domain wrong")
	}
	if guiFmtBytes(1023) != "1023 B" || guiFmtBytes(2560) != "3 KB" || guiFmtBytes(1048576) != "1.0 MB" {
		t.Fatalf("fmtBytes wrong: %s %s %s", guiFmtBytes(1023), guiFmtBytes(2560), guiFmtBytes(1048576))
	}
}
