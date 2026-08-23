/*
* Contains logic for a device's identity within a snadbox:
*
* - A friendly adjective-toy name (see components.GenerateName)
* - An ephemeral self-signed TLS certificate, generated fresh per process
* - The SHA-256 fingerprint of that certificate, which is what gets
*   advertised over UDP discovery and pinned by peers on TCP connect
*   (trust-on-first-use, no CA involved — see protocol.go)
 */

package snadbox

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"time"

	"snad/components"
)

type Identity struct {
	Name        string
	Fingerprint [32]byte
	Cert        tls.Certificate
}

// generateSelfSignedCert creates an ephemeral ECDSA P-256 certificate valid
// for the lifetime of this process, along with the SHA-256 fingerprint of
// its DER encoding.
func generateSelfSignedCert() (tls.Certificate, [32]byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, [32]byte{}, fmt.Errorf("generate key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, [32]byte{}, fmt.Errorf("generate serial: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "snad"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, [32]byte{}, fmt.Errorf("create certificate: %w", err)
	}

	cert := tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
	}

	return cert, sha256.Sum256(der), nil
}

// NewIdentity generates a fresh adjective-toy name (unique against taken)
// and a self-signed TLS certificate to represent this device for the
// lifetime of the process.
func NewIdentity(taken components.Set[string]) (Identity, error) {
	cert, fingerprint, err := generateSelfSignedCert()
	if err != nil {
		return Identity{}, err
	}

	name, err := components.GenerateName(taken)
	if err != nil {
		return Identity{}, fmt.Errorf("generate name: %w", err)
	}

	return Identity{
		Name:        name,
		Fingerprint: fingerprint,
		Cert:        cert,
	}, nil
}

// sign produces an ECDSA (ASN.1 DER) signature over digest using this
// identity's private key -- the generic "prove I hold the key behind my
// certificate" primitive that UDP discovery builds its message
// authentication on (see snadbox.go's hashDiscoveryPayload/announce).
func (id Identity) sign(digest []byte) ([]byte, error) {
	key, ok := id.Cert.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("identity private key is not ECDSA")
	}
	return ecdsa.SignASN1(rand.Reader, key, digest)
}
