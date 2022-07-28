/*
 * Vault Kubernetes Secrets Engine is a plugin for
 * generating dynamic kubernetes credentials with
 * Hashicorp Vault
 *
 * Contact: pedro.tonini@hotmail.com
 *
 * Vault Kubernetes Secrets Engine is free software; you can
 * redistribute it and/or modify it under the terms of the
 * GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * Vault Kubernetes Secrets Engine is distributed in the hope that
 * it will be useful, but WITHOUT ANY WARRANTY; without even the
 * implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU Lesser General Public License for more details.
 */

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

// createKeyAndCertificateRequest return a key pair for signing
// by a external certificate authority
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

// createKeyAndSelfSignedCertificate return a key pair for testing
// purposes
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

// pemEncode add the PEM type headers and footers to
// the provided byte slice and returns a string
func pemEncode(b []byte, t string) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: t, Bytes: b}))
}

// base64Encode converts the given string to bas64 format
func base64Encode(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

// parseCertificate takes a PEM formatted certificate
// string and parses it into a x509 struct
func parseCertificate(c string) (*x509.Certificate, error) {
	b, _ := pem.Decode([]byte(c))
	return x509.ParseCertificate(b.Bytes)
}
