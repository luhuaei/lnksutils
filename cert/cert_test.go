package cert_test

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"

	"github.com/linakesi/lnksutils/cert"
	"github.com/stretchr/testify/require"
)

func TestRsa(t *testing.T) {
	buf := bytes.NewBuffer(nil)

	err := cert.GeneratePEMRSA(buf)
	require.Nil(t, err)

	_rsaPriv, err := cert.ParsePEMPrivateKey(buf.Bytes())
	require.Nil(t, err)
	rsaPriv := _rsaPriv.(*rsa.PrivateKey)

	payload := []byte("payload")

	sign, err := cert.RSASignPKCS1v15(rsaPriv, payload)
	require.Nil(t, err)

	pub := rsaPriv.Public()
	err = cert.RSAVerifyPKCS1v15(pub.(*rsa.PublicKey), payload, sign)
	require.Nil(t, err)
}

func TestCert(t *testing.T) {
	// create random key as root key
	buf := bytes.NewBuffer(nil)
	err := cert.GeneratePEMRSA(buf)
	require.Nil(t, err)

	_rootPrik, err := cert.ParsePEMPrivateKey(buf.Bytes())
	require.Nil(t, err)
	rootPrik := _rootPrik.(*rsa.PrivateKey)

	// child random key
	buf.Reset()
	cert.GeneratePEMRSA(buf)
	_childPrik, err := cert.ParsePEMPrivateKey(buf.Bytes())
	require.Nil(t, err)
	childPrik := _childPrik.(*rsa.PrivateKey)

	// create root cert
	rootCert, err := cert.CreateSelfSignCert(pkix.Name{
		CommonName: "linakesi.com",
	}, time.Minute, rootPrik)
	require.Nil(t, err)

	// children cert request
	csr, err := cert.GenerateCSR(childPrik, pkix.Name{
		CommonName: "child.linakesi.com",
	})
	require.Nil(t, err)

	childCert, err := cert.IssueCert(rootCert, rootPrik, time.Minute, csr)
	require.Nil(t, err)

	// verfiy child cert
	roots := x509.NewCertPool()
	roots.AddCert(rootCert)

	_, err = childCert.Verify(x509.VerifyOptions{
		Roots: roots,
	})
	require.Nil(t, err)
}
