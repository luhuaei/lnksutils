package cert

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
)

// GeneratePEMRSA generate RSA private key use rand.Reader with 4096 bits
func GeneratePEMRSA(w io.Writer) error {
	k, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return err
	}

	b, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return err
	}

	return pem.Encode(w, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: b,
	})
}

// ParsePEMPrivateKey parse PEM format private key.
//
// It returns a *rsa.PrivateKey, a *ecdsa.PrivateKey, or a ed25519.PrivateKey.
func ParsePEMPrivateKey(b []byte) (crypto.PrivateKey, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("failed to parse Private Key")
	}

	switch block.Type {
	case "PRIVATE KEY":
		return x509.ParsePKCS8PrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("Not support Private Key type: %s", block.Type)
	}
}

// RSASignPKCS1v15 sign payload with SHA256
func RSASignPKCS1v15(priKey *rsa.PrivateKey, payload []byte) ([]byte, error) {
	sha := sha256.New()
	sha.Write(payload)

	return rsa.SignPKCS1v15(nil, priKey, crypto.SHA256, sha.Sum(nil))
}

// RSAVerifyPKCS1v15 verify payload with SHA256
func RSAVerifyPKCS1v15(pubKey *rsa.PublicKey, payload []byte, sign []byte) error {
	sha := sha256.New()
	sha.Write(payload)

	return rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, sha.Sum(nil), sign)
}
