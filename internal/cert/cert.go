package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"time"
)

type CertKeyPair struct {
	Key  *rsa.PrivateKey
	Cert *x509.Certificate
}

func GenerateKeyAndCert(dnsNames []string, caCert *x509.Certificate, caKey *rsa.PrivateKey) (*CertKeyPair, error) {
	// Generate a private key for the new server certificate.
	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	serialNumber, err := rand.Int(
		rand.Reader,
		new(big.Int).Lsh(big.NewInt(1), 128),
	)
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,

		NotBefore: time.Now().Add(-5 * time.Minute),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),

		// These are the hostnames TLS verification uses.
		DNSNames: dnsNames,

		KeyUsage: x509.KeyUsageDigitalSignature |
			x509.KeyUsageKeyEncipherment,

		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},

		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(
		rand.Reader,
		template,             // certificate being created
		caCert,               // issuer
		&serverKey.PublicKey, // subject public key
		caKey,                // CA private key
	)
	if err != nil {
		return nil, err
	}

	signedCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}
	return &CertKeyPair{Key: serverKey, Cert: signedCert}, nil
}

func LoadCert(path string) (*x509.Certificate, error) {
	certPEM, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, err
	}

	caCert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, err
	}

	return caCert, nil
}

func LoadKey(path string) (*rsa.PrivateKey, error) {
	keyPEM, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, errors.New("invalid CA private key PEM")
	}

	key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, err
	}

	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("invalid key")
	}

	return rsaKey, nil
}
