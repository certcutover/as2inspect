// Package certs parses public X.509 certificates and infers their likely role
// in an AS2 trading-partner relationship. It never accepts or stores private
// keys: any PEM private-key block or PKCS#12/PFX input is rejected before parse.
package certs

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// ErrPrivateKey is returned when the input contains private key material. The
// inspector is a public-certificate tool by design; accepting a private key
// would be a critical safety failure, so we refuse before doing anything else.
var ErrPrivateKey = errors.New("input contains a private key; this tool only accepts public certificates — never upload private keys or PFX/PKCS#12 files")

// Role is the inferred purpose of a certificate within an AS2 setup.
type Role string

const (
	RoleSigning    Role = "signing"        // digital signature (AS2 message signing)
	RoleEncryption Role = "encryption"     // key encipherment (AS2 message encryption)
	RoleTLS        Role = "endpoint-tls"   // server auth (HTTPS AS2 endpoint)
	RoleDualUse    Role = "signing+encryption"
	RoleUnknown    Role = "unknown"
)

// Urgency buckets an expiry against the rollover windows the product tracks.
type Urgency string

const (
	UrgencyExpired  Urgency = "expired"
	UrgencyCritical Urgency = "critical" // <14 days
	UrgencyWarning  Urgency = "warning"  // <60 days
	UrgencyPlan     Urgency = "plan"     // <120 days
	UrgencyOK       Urgency = "ok"
)

// Report is the structured result of inspecting one certificate. It is shaped
// so the same struct backs the CLI, the web tool, and later the hosted API.
type Report struct {
	Subject          string    `json:"subject"`
	Issuer           string    `json:"issuer"`
	SelfSigned       bool      `json:"self_signed"`
	SerialNumber     string    `json:"serial_number"`
	NotBefore        time.Time `json:"not_before"`
	NotAfter         time.Time `json:"not_after"`
	DaysToExpiry     int       `json:"days_to_expiry"`
	Urgency          Urgency   `json:"urgency"`
	Role             Role      `json:"role"`
	RoleConfidence   string    `json:"role_confidence"` // "high" | "inferred"
	PublicKeyType    string    `json:"public_key_type"`
	PublicKeyBits    int       `json:"public_key_bits"`
	SignatureAlgo    string    `json:"signature_algorithm"`
	WeakSignature    bool      `json:"weak_signature"` // SHA-1 / MD5 based
	SHA1Fingerprint  string    `json:"sha1_fingerprint"`
	SHA256Fingerprint string   `json:"sha256_fingerprint"`
	KeyUsages        []string  `json:"key_usages"`
	ExtKeyUsages     []string  `json:"ext_key_usages"`
	DNSNames         []string  `json:"dns_names,omitempty"`
	Warnings         []string  `json:"warnings,omitempty"`
}

// guardPrivateKey scans raw input for anything that looks like private key
// material and refuses it. This runs before any parse attempt.
func guardPrivateKey(raw []byte) error {
	// PEM private-key block types (PKCS#1, PKCS#8, SEC1, and legacy variants).
	text := string(raw)
	// "PRIVATE KEY" covers RSA/EC/DSA/OPENSSH PKCS#1/SEC1/PKCS#8 blocks;
	// "ENCRYPTED PRIVATE" covers encrypted PKCS#8.
	if strings.Contains(text, "PRIVATE KEY") || strings.Contains(text, "ENCRYPTED PRIVATE") {
		return ErrPrivateKey
	}
	// PKCS#12/PFX is DER (binary) and has no PEM header. Detect by its ASN.1
	// prelude: SEQUENCE followed by INTEGER version 3. This is a heuristic, but
	// it errs toward rejecting anything key-bearing.
	if len(raw) >= 4 && raw[0] == 0x30 && (raw[1] == 0x82 || raw[1] == 0x83) {
		// Look for the PKCS#12 version integer (02 01 03) shortly after the header.
		window := raw
		if len(window) > 16 {
			window = window[:16]
		}
		if strings.Contains(string(window), string([]byte{0x02, 0x01, 0x03})) {
			return ErrPrivateKey
		}
	}
	return nil
}

// Inspect parses a single public certificate from PEM or DER bytes and returns
// a Report. It rejects private-key input outright.
func Inspect(raw []byte, now time.Time) (*Report, error) {
	if err := guardPrivateKey(raw); err != nil {
		return nil, err
	}

	der, err := toDER(raw)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("not a valid X.509 certificate: %w", err)
	}

	r := &Report{
		Subject:       cert.Subject.String(),
		Issuer:        cert.Issuer.String(),
		SelfSigned:    cert.Subject.String() == cert.Issuer.String(),
		SerialNumber:  cert.SerialNumber.String(),
		NotBefore:     cert.NotBefore,
		NotAfter:      cert.NotAfter,
		SignatureAlgo: cert.SignatureAlgorithm.String(),
	}

	r.DaysToExpiry = int(cert.NotAfter.Sub(now).Hours() / 24)
	r.Urgency = classifyUrgency(cert, now)
	r.SHA1Fingerprint = fingerprint(sha1.Sum(der))
	r.SHA256Fingerprint = fingerprintSHA256(sha256.Sum256(der))
	r.KeyUsages = describeKeyUsage(cert.KeyUsage)
	r.ExtKeyUsages = describeExtKeyUsage(cert.ExtKeyUsage)
	r.DNSNames = cert.DNSNames
	r.PublicKeyType, r.PublicKeyBits = describeKey(cert)
	r.Role, r.RoleConfidence = inferRole(cert)
	r.WeakSignature = isWeakSignature(cert.SignatureAlgorithm)

	r.Warnings = collectWarnings(r, cert, now)
	return r, nil
}

func toDER(raw []byte) ([]byte, error) {
	trimmed := strings.TrimSpace(string(raw))
	if strings.HasPrefix(trimmed, "-----BEGIN") {
		block, _ := pem.Decode([]byte(trimmed))
		if block == nil {
			return nil, errors.New("input looks like PEM but no valid block could be decoded")
		}
		if !strings.Contains(block.Type, "CERTIFICATE") {
			return nil, fmt.Errorf("PEM block is %q, expected a CERTIFICATE", block.Type)
		}
		return block.Bytes, nil
	}
	// Assume DER.
	return raw, nil
}

func classifyUrgency(cert *x509.Certificate, now time.Time) Urgency {
	switch {
	case now.After(cert.NotAfter):
		return UrgencyExpired
	case cert.NotAfter.Sub(now) < 14*24*time.Hour:
		return UrgencyCritical
	case cert.NotAfter.Sub(now) < 60*24*time.Hour:
		return UrgencyWarning
	case cert.NotAfter.Sub(now) < 120*24*time.Hour:
		return UrgencyPlan
	default:
		return UrgencyOK
	}
}

// inferRole maps X.509 key usage to an AS2 role. Signing/encryption come
// straight from KeyUsage bits (high confidence); TLS from serverAuth EKU.
func inferRole(cert *x509.Certificate) (Role, string) {
	hasSign := cert.KeyUsage&x509.KeyUsageDigitalSignature != 0
	hasEncrypt := cert.KeyUsage&(x509.KeyUsageKeyEncipherment|x509.KeyUsageDataEncipherment) != 0

	if slices.Contains(cert.ExtKeyUsage, x509.ExtKeyUsageServerAuth) {
		return RoleTLS, "high"
	}

	switch {
	case hasSign && hasEncrypt:
		return RoleDualUse, "high"
	case hasSign:
		return RoleSigning, "high"
	case hasEncrypt:
		return RoleEncryption, "high"
	}

	// No usable KeyUsage bits: many AS2 certs are self-signed with no usage
	// constraints, so fall back to dual-use as the safe AS2 assumption.
	return RoleDualUse, "inferred"
}

func describeKey(cert *x509.Certificate) (string, int) {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return "RSA", pub.N.BitLen()
	case *ecdsa.PublicKey:
		return "ECDSA", pub.Curve.Params().BitSize
	case ed25519.PublicKey:
		return "Ed25519", 256
	default:
		return "unknown", 0
	}
}

func isWeakSignature(algo x509.SignatureAlgorithm) bool {
	switch algo {
	case x509.MD2WithRSA, x509.MD5WithRSA,
		x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1:
		return true
	default:
		return false
	}
}

func collectWarnings(r *Report, cert *x509.Certificate, now time.Time) []string {
	var w []string
	if r.Urgency == UrgencyExpired {
		w = append(w, fmt.Sprintf("Certificate expired %d days ago — AS2 traffic using it will fail.", -r.DaysToExpiry))
	}
	if r.WeakSignature {
		w = append(w, "Weak signature algorithm (SHA-1/MD5). Some partners reject these; plan replacement.")
	}
	if r.PublicKeyType == "RSA" && r.PublicKeyBits < 2048 {
		w = append(w, fmt.Sprintf("RSA key is only %d bits; 2048+ is expected for AS2.", r.PublicKeyBits))
	}
	if now.Before(cert.NotBefore) {
		w = append(w, "Certificate is not yet valid (notBefore is in the future).")
	}
	if r.RoleConfidence == "inferred" {
		w = append(w, "No KeyUsage extension present; role inferred as dual-use signing+encryption (common for AS2 self-signed certs).")
	}
	return w
}

func describeKeyUsage(ku x509.KeyUsage) []string {
	var out []string
	pairs := []struct {
		bit  x509.KeyUsage
		name string
	}{
		{x509.KeyUsageDigitalSignature, "DigitalSignature"},
		{x509.KeyUsageContentCommitment, "ContentCommitment"},
		{x509.KeyUsageKeyEncipherment, "KeyEncipherment"},
		{x509.KeyUsageDataEncipherment, "DataEncipherment"},
		{x509.KeyUsageKeyAgreement, "KeyAgreement"},
		{x509.KeyUsageCertSign, "CertSign"},
		{x509.KeyUsageCRLSign, "CRLSign"},
	}
	for _, p := range pairs {
		if ku&p.bit != 0 {
			out = append(out, p.name)
		}
	}
	return out
}

func describeExtKeyUsage(ekus []x509.ExtKeyUsage) []string {
	names := map[x509.ExtKeyUsage]string{
		x509.ExtKeyUsageServerAuth:      "ServerAuth",
		x509.ExtKeyUsageClientAuth:      "ClientAuth",
		x509.ExtKeyUsageEmailProtection: "EmailProtection",
		x509.ExtKeyUsageCodeSigning:     "CodeSigning",
	}
	var out []string
	for _, e := range ekus {
		if n, ok := names[e]; ok {
			out = append(out, n)
		}
	}
	return out
}

func fingerprint(sum [20]byte) string      { return colonHex(sum[:]) }
func fingerprintSHA256(sum [32]byte) string { return colonHex(sum[:]) }

func colonHex(b []byte) string {
	h := hex.EncodeToString(b)
	var sb strings.Builder
	for i := 0; i < len(h); i += 2 {
		if i > 0 {
			sb.WriteByte(':')
		}
		sb.WriteString(strings.ToUpper(h[i : i+2]))
	}
	return sb.String()
}
