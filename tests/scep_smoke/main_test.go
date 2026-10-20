package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"math/big"
	"testing"
	"time"
)

func TestSCEPEncryptionRecipients(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := func(usage x509.KeyUsage, publicKey any) *x509.Certificate {
		t.Helper()
		template := &x509.Certificate{
			SerialNumber: big.NewInt(int64(usage)),
			NotBefore:    time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
			KeyUsage: usage, IsCA: usage&x509.KeyUsageCertSign != 0, BasicConstraintsValid: true,
		}
		der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return cert
	}
	ca := certificate(x509.KeyUsageCertSign|x509.KeyUsageCRLSign, &key.PublicKey)
	issuer := certificate(ca.KeyUsage|x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment, &key.PublicKey)
	signing := certificate(x509.KeyUsageDigitalSignature, &key.PublicKey)
	encryption := certificate(x509.KeyUsageKeyEncipherment, &key.PublicKey)
	nonRSA := certificate(x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment, &ecKey.PublicKey)
	for _, tc := range []struct {
		name         string
		certificates []*x509.Certificate
		want         []*x509.Certificate
	}{
		{"empty response", nil, nil},
		{"old CA only usages", []*x509.Certificate{ca, ca}, nil},
		{"SCEP issuer filters root", []*x509.Certificate{ca, issuer}, []*x509.Certificate{issuer}},
		{"separate RA roles", []*x509.Certificate{ca, signing, encryption}, []*x509.Certificate{encryption}},
		{"missing signing", []*x509.Certificate{ca, encryption}, nil},
		{"missing encryption", []*x509.Certificate{ca, signing}, nil},
		{"non RSA encryption", []*x509.Certificate{ca, nonRSA}, nil},
		{"mixed public keys", []*x509.Certificate{ca, nonRSA, issuer}, []*x509.Certificate{issuer}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := scepEncryptionRecipients(tc.certificates)
			if tc.want == nil {
				if err == nil || len(got) != 0 {
					t.Fatal("unsuitable SCEP CA response accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("got %d recipients, want %d", len(got), len(tc.want))
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatal("selected an ineligible encryption recipient")
				}
			}
		})
	}
}
