package cert

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math"
	"math/big"
	"time"
)

// GenerateCSR create certificate request file with subject info.
func GenerateCSR(prikey crypto.PrivateKey, subject pkix.Name) (*x509.CertificateRequest, error) {
	var sigAlgo x509.SignatureAlgorithm
	switch prikey.(type) {
	case *rsa.PrivateKey:
		sigAlgo = x509.SHA512WithRSA
	case *ecdsa.PrivateKey:
		sigAlgo = x509.ECDSAWithSHA1
	case *ed25519.PrivateKey:
		sigAlgo = x509.PureEd25519
	default:
		return nil, errors.New("not supported private key type.")
	}

	b, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:            subject,
		SignatureAlgorithm: sigAlgo,
	}, prikey)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificateRequest(b)
}

func ParseCSRPEM(r io.Reader) (*x509.CertificateRequest, error) {
	b, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(b)
	return x509.ParseCertificateRequest(block.Bytes)
}

func CSRToPEM(csr *x509.CertificateRequest, w io.Writer) error {
	return pem.Encode(w, &pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csr.Raw,
	})
}

func CreateSelfSignCert(subject pkix.Name, expiration time.Duration,
	prikey crypto.PrivateKey) (*x509.Certificate, error) {

	var pubk crypto.PublicKey
	switch prikey.(type) {
	case *rsa.PrivateKey:
		p := prikey.(*rsa.PrivateKey)
		pubk = p.Public()
	case *ecdsa.PrivateKey:
		p := prikey.(*ecdsa.PrivateKey)
		pubk = p.Public()
	case *ed25519.PrivateKey:
		p := prikey.(*ed25519.PrivateKey)
		pubk = p.Public()
	default:
		return nil, errors.New("not supported private key type.")
	}

	serial, err := rand.Int(rand.Reader, (&big.Int{}).Exp(big.NewInt(2), big.NewInt(159), big.NewInt(0)))
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber:          serial,
		Subject:               subject,
		Issuer:                subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(expiration),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}

	b, err := x509.CreateCertificate(rand.Reader, &template, &template, pubk, prikey)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(b)
}

func CertToPEM(cert *x509.Certificate, w io.Writer) error {
	return pem.Encode(w, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
}

func IssueCert(parentCert *x509.Certificate, parentPrivateKey crypto.PrivateKey, expire time.Duration,
	csr *x509.CertificateRequest) (*x509.Certificate, error) {

	template := x509.Certificate{
		SerialNumber: big.NewInt(math.MaxInt64),
		Subject:      csr.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(expire),
	}

	_childCert, err := x509.CreateCertificate(rand.Reader, &template, parentCert, csr.PublicKey, parentPrivateKey)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(_childCert)
}

func ParseCertPEM(r io.Reader) (*x509.Certificate, error) {
	crtPEM, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode([]byte(crtPEM))
	if block == nil {
		return nil, errors.New("failed to load PEM CERT")
	}
	return x509.ParseCertificate(block.Bytes)
}
