package certs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// fixedNow keeps urgency/expiry math deterministic across the suite.
var fixedNow = time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)

// makeCert builds a self-signed cert with the given usage and validity window
// and returns its PEM encoding. Generating fixtures in-code is the whole point:
// X.509 is fully specified, so we owe nothing to external sample data.
func makeCert(t *testing.T, cn string, ku x509.KeyUsage, eku []x509.ExtKeyUsage, notBefore, notAfter time.Time, algo x509.SignatureAlgorithm, dnsNames []string) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:       big.NewInt(1),
		Subject:            pkix.Name{CommonName: cn},
		NotBefore:          notBefore,
		NotAfter:           notAfter,
		KeyUsage:           ku,
		ExtKeyUsage:        eku,
		DNSNames:           dnsNames,
		SignatureAlgorithm: algo,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestInspect_SigningRole(t *testing.T) {
	pemBytes := makeCert(t, "AcmeCorp AS2 Signing", x509.KeyUsageDigitalSignature, nil,
		fixedNow.AddDate(0, -1, 0), fixedNow.AddDate(1, 0, 0), x509.SHA256WithRSA, nil)

	r, err := Inspect(pemBytes, fixedNow)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Role != RoleSigning {
		t.Errorf("role = %q, want %q", r.Role, RoleSigning)
	}
	if r.RoleConfidence != "high" {
		t.Errorf("confidence = %q, want high", r.RoleConfidence)
	}
	if !r.SelfSigned {
		t.Error("expected self-signed = true")
	}
	if r.Urgency != UrgencyOK {
		t.Errorf("urgency = %q, want ok", r.Urgency)
	}
	if r.PublicKeyBits != 2048 {
		t.Errorf("bits = %d, want 2048", r.PublicKeyBits)
	}
}

func TestInspect_EncryptionRole(t *testing.T) {
	pemBytes := makeCert(t, "AcmeCorp AS2 Encryption", x509.KeyUsageKeyEncipherment, nil,
		fixedNow.AddDate(0, -1, 0), fixedNow.AddDate(1, 0, 0), x509.SHA256WithRSA, nil)
	r, err := Inspect(pemBytes, fixedNow)
	if err != nil {
		t.Fatal(err)
	}
	if r.Role != RoleEncryption {
		t.Errorf("role = %q, want %q", r.Role, RoleEncryption)
	}
}

func TestInspect_TLSRole(t *testing.T) {
	pemBytes := makeCert(t, "as2.example.com", x509.KeyUsageDigitalSignature,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		fixedNow.AddDate(0, -1, 0), fixedNow.AddDate(0, 6, 0), x509.SHA256WithRSA,
		[]string{"as2.example.com"})
	r, err := Inspect(pemBytes, fixedNow)
	if err != nil {
		t.Fatal(err)
	}
	if r.Role != RoleTLS {
		t.Errorf("role = %q, want %q (serverAuth EKU must win)", r.Role, RoleTLS)
	}
	if len(r.DNSNames) != 1 || r.DNSNames[0] != "as2.example.com" {
		t.Errorf("dns names = %v, want [as2.example.com]", r.DNSNames)
	}
}

func TestInspect_DualUseWhenNoUsageBits(t *testing.T) {
	pemBytes := makeCert(t, "Legacy Partner AS2", 0, nil,
		fixedNow.AddDate(0, -1, 0), fixedNow.AddDate(1, 0, 0), x509.SHA256WithRSA, nil)
	r, err := Inspect(pemBytes, fixedNow)
	if err != nil {
		t.Fatal(err)
	}
	if r.Role != RoleDualUse {
		t.Errorf("role = %q, want %q", r.Role, RoleDualUse)
	}
	if r.RoleConfidence != "inferred" {
		t.Errorf("confidence = %q, want inferred", r.RoleConfidence)
	}
}

func TestInspect_UrgencyBuckets(t *testing.T) {
	cases := []struct {
		name string
		days int
		want Urgency
	}{
		{"expired", -5, UrgencyExpired},
		{"critical", 7, UrgencyCritical},
		{"warning", 45, UrgencyWarning},
		{"plan", 90, UrgencyPlan},
		{"ok", 300, UrgencyOK},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pemBytes := makeCert(t, "Expiry Test", x509.KeyUsageDigitalSignature, nil,
				fixedNow.AddDate(-1, 0, 0), fixedNow.Add(time.Duration(c.days)*24*time.Hour),
				x509.SHA256WithRSA, nil)
			r, err := Inspect(pemBytes, fixedNow)
			if err != nil {
				t.Fatal(err)
			}
			if r.Urgency != c.want {
				t.Errorf("days=%d urgency = %q, want %q", c.days, r.Urgency, c.want)
			}
		})
	}
}

func TestInspect_WeakSignatureWarning(t *testing.T) {
	pemBytes := makeCert(t, "Old Partner", x509.KeyUsageDigitalSignature, nil,
		fixedNow.AddDate(0, -1, 0), fixedNow.AddDate(1, 0, 0), x509.SHA1WithRSA, nil)
	r, err := Inspect(pemBytes, fixedNow)
	if err != nil {
		t.Fatal(err)
	}
	if !r.WeakSignature {
		t.Error("expected weak signature flag for SHA1WithRSA")
	}
	if !hasWarningContaining(r.Warnings, "Weak signature") {
		t.Errorf("expected a weak-signature warning, got %v", r.Warnings)
	}
}

// The safety-critical test: private keys must never be accepted.
func TestInspect_RejectsPrivateKeyPEM(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	der := x509.MarshalPKCS1PrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})

	_, err := Inspect(keyPEM, fixedNow)
	if err != ErrPrivateKey {
		t.Fatalf("err = %v, want ErrPrivateKey", err)
	}
}

func TestInspect_RejectsPKCS8PrivateKey(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if _, err := Inspect(keyPEM, fixedNow); err != ErrPrivateKey {
		t.Fatalf("err = %v, want ErrPrivateKey", err)
	}
}

func TestInspect_RejectsGarbage(t *testing.T) {
	if _, err := Inspect([]byte("this is not a certificate"), fixedNow); err == nil {
		t.Fatal("expected an error for garbage input")
	}
}

func hasWarningContaining(warnings []string, substr string) bool {
	for _, w := range warnings {
		if len(w) >= len(substr) && containsFold(w, substr) {
			return true
		}
	}
	return false
}

func containsFold(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
