package secretsengine

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
)

func createKeyAndCertificateRequest(subjectName string) (*rsa.PrivateKey, []byte) {
	key, _ := rsa.GenerateKey(rand.Reader, rsaKeyLength)
	subject := pkix.Name{CommonName: subjectName}
	encodedSubject, _ := asn1.Marshal(subject.ToRDNSequence())
	csrReq := x509.CertificateRequest{
		RawSubject:         encodedSubject,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}
	csr, _ := x509.CreateCertificateRequest(rand.Reader, &csrReq, key)
	return key, csr
}

func encodeSecretKey(key *rsa.PrivateKey) string {
	keyDer := x509.MarshalPKCS1PrivateKey(key)
	return base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyDer}))
}

func parseCertificate(encodedCert string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(encodedCert))
	return x509.ParseCertificate(block.Bytes)
}
