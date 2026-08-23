package snadbox

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"testing"
	"time"
)

func TestNewIdentityFingerprintMatchesCert(t *testing.T) {
	id := NewTestIdentity(t)

	der := id.Cert.Certificate[0]
	want := sha256.Sum256(der)
	if id.Fingerprint != want {
		t.Fatalf("fingerprint does not match cert DER hash: got %x want %x", id.Fingerprint, want)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	if _, ok := cert.PublicKey.(*ecdsa.PublicKey); !ok {
		t.Fatalf("expected ECDSA public key, got %T", cert.PublicKey)
	}

	now := time.Now()
	if cert.NotBefore.After(now) || cert.NotAfter.Before(now) {
		t.Fatalf("cert is not currently valid: NotBefore=%v NotAfter=%v now=%v", cert.NotBefore, cert.NotAfter, now)
	}
	if cert.NotAfter.Sub(cert.NotBefore) < 23*time.Hour {
		t.Fatalf("expected ~24h validity window, got %v", cert.NotAfter.Sub(cert.NotBefore))
	}
}

func TestIdentitySignVerifiesAgainstOwnCert(t *testing.T) {
	id := NewTestIdentity(t)

	digest := sha256.Sum256([]byte("some payload"))
	sig, err := id.sign(digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	cert, err := x509.ParseCertificate(id.Cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("expected ECDSA public key, got %T", cert.PublicKey)
	}
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		t.Fatal("signature failed to verify against the identity's own certificate")
	}

	other := NewTestIdentity(t)
	otherCert, err := x509.ParseCertificate(other.Cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse other cert: %v", err)
	}
	otherPub := otherCert.PublicKey.(*ecdsa.PublicKey)
	if ecdsa.VerifyASN1(otherPub, digest[:], sig) {
		t.Fatal("signature incorrectly verified against a different identity's certificate")
	}
}

func TestNewIdentityAvoidsTakenNames(t *testing.T) {
	first := NewTestIdentity(t)

	taken := CreateTestSet(first.Name)
	second, err := NewIdentity(taken)
	if err != nil {
		t.Fatalf("NewIdentity: %v", err)
	}
	if second.Name == first.Name {
		t.Fatalf("NewIdentity returned a name already in taken: %s", second.Name)
	}
}
