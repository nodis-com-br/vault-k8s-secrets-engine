package secretsengine

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
)

func createKeyAndCertificateRequest(subjectName string, keyLength int) (string, []byte) {
	key, _ := rsa.GenerateKey(rand.Reader, keyLength)
	keyDer := x509.MarshalPKCS1PrivateKey(key)
	csrTemplate := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: subjectName,
		},
		SignatureAlgorithm: x509.SHA256WithRSA,
	}
	csr, _ := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, key)
	return pemEncode(keyDer, "RSA PRIVATE KEY"), csr
}

func createKeyAndSelfSignedCertificate(subjectName string, keyLength int) (string, string) {
	key, _ := rsa.GenerateKey(rand.Reader, keyLength)
	keyDer := x509.MarshalPKCS1PrivateKey(key)
	certTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: subjectName,
		},
		SignatureAlgorithm: x509.SHA256WithRSA,
	}
	certDer, _ := x509.CreateCertificate(rand.Reader, &certTemplate, &certTemplate, &key.PublicKey, key)
	return pemEncode(keyDer, "RSA PRIVATE KEY"), pemEncode(certDer, "CERTIFICATE")
}

func pemEncode(b []byte, t string) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: t, Bytes: b}))
}

func base64Encode(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

func parseCertificate(c string) (*x509.Certificate, error) {
	b, _ := pem.Decode([]byte(c))
	return x509.ParseCertificate(b.Bytes)
}
