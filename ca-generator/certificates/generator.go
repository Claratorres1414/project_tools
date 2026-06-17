package certificates

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"time"
)

type Artifacts struct {
	PrivateKey []byte

	PublicKey []byte

	Certificate []byte
}

func GenerateCA() (*Artifacts, error) {

	privateKey, err :=
		ecdsa.GenerateKey(
			elliptic.P256(),
			rand.Reader,
		)

	if err != nil {
		return nil, err
	}

	serialNumber, err :=
		rand.Int(
			rand.Reader,
			new(big.Int).Lsh(
				big.NewInt(1),
				128,
			),
		)

	if err != nil {
		return nil, err
	}

	template := x509.Certificate{

		SerialNumber: serialNumber,

		Subject: pkix.Name{

			CommonName: "CryptOwl Root CA",

			Organization: []string{
				"CryptOwl",
			},

			OrganizationalUnit: []string{
				"Document Signature Authority",
			},

			Country: []string{
				"BR",
			},
		},

		NotBefore: time.Now(),

		NotAfter: time.Now().AddDate(
			20,
			0,
			0,
		),

		IsCA: true,

		BasicConstraintsValid: true,

		KeyUsage: x509.KeyUsageDigitalSignature |
			x509.KeyUsageCertSign |
			x509.KeyUsageCRLSign,
	}

	certificateBytes, err :=
		x509.CreateCertificate(

			rand.Reader,

			&template,

			&template,

			&privateKey.PublicKey,

			privateKey,
		)

	if err != nil {
		return nil, err
	}

	privateKeyBytes, err :=
		x509.MarshalPKCS8PrivateKey(
			privateKey,
		)

	if err != nil {
		return nil, err
	}

	publicKeyBytes, err :=
		x509.MarshalPKIXPublicKey(
			&privateKey.PublicKey,
		)

	if err != nil {
		return nil, err
	}

	privateKeyPem :=
		pem.EncodeToMemory(
			&pem.Block{
				Type: "PRIVATE KEY",

				Bytes: privateKeyBytes,
			},
		)

	publicKeyPem :=
		pem.EncodeToMemory(
			&pem.Block{
				Type: "PUBLIC KEY",

				Bytes: publicKeyBytes,
			},
		)

	certificatePem :=
		pem.EncodeToMemory(
			&pem.Block{

				Type: "CERTIFICATE",

				Bytes: certificateBytes,
			},
		)

	return &Artifacts{

		PrivateKey: privateKeyPem,

		PublicKey: publicKeyPem,

		Certificate: certificatePem,
	}, nil
}
