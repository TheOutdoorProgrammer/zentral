// This integration test uses synthetic identities and keeps challenges and private keys in memory.
package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"time"

	"github.com/smallstep/pkcs7"
	"github.com/smallstep/scep"
	"github.com/smallstep/scep/x509util"
)

type input struct {
	URL          string `json:"url"`
	Host         string `json:"host"`
	RootFile     string `json:"root_file"`
	Challenge    string `json:"challenge"`
	CommonName   string `json:"common_name"`
	Organization string `json:"organization"`
	SerialNumber string `json:"serial_number"`
}

type probe struct {
	config        input
	client        *http.Client
	roots         *x509.CertPool
	intermediates *x509.CertPool
	certificates  []*x509.Certificate
	key           *rsa.PrivateKey
	signer        *x509.Certificate
}

func (p *probe) request(operation string, body []byte) ([]byte, error) {
	u, err := url.Parse(p.config.URL)
	if err != nil {
		return nil, errors.New("invalid endpoint")
	}
	query := u.Query()
	query.Set("operation", operation)
	u.RawQuery = query.Encode()
	method := http.MethodGet
	if body != nil {
		method = http.MethodPost
	}
	req, err := http.NewRequest(method, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, errors.New("request creation failed")
	}
	req.Host = p.config.Host
	req.Header.Set("Content-Type", "application/x-pki-message")
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, errors.New("SCEP transport failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("SCEP HTTP status %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, (2<<20)+1))
	if err != nil || len(data) > 2<<20 {
		return nil, errors.New("invalid SCEP response size")
	}
	return data, nil
}

func (p *probe) message(commonName string) (*scep.PKIMessage, error) {
	csrBytes, err := x509util.CreateCertificateRequest(rand.Reader, &x509util.CertificateRequest{
		CertificateRequest: x509.CertificateRequest{
			Subject: pkix.Name{
				CommonName: commonName, Organization: []string{p.config.Organization},
				SerialNumber: p.config.SerialNumber,
			},
			SignatureAlgorithm: x509.SHA256WithRSA,
		},
		ChallengePassword: p.config.Challenge,
	}, p.key)
	if err != nil {
		return nil, errors.New("CSR generation failed")
	}
	csr, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		return nil, errors.New("CSR parsing failed")
	}
	msg, err := scep.NewCSRRequest(csr, &scep.PKIMessage{
		MessageType: scep.PKCSReq, Recipients: p.certificates,
		SignerCert: p.signer, SignerKey: p.key,
	})
	if err != nil {
		return nil, errors.New("PKCSReq generation failed")
	}
	return msg, nil
}

func (p *probe) exchange(msg *scep.PKIMessage, success bool) error {
	data, err := p.request("PKIOperation", msg.Raw)
	if err != nil {
		return err
	}
	reply, err := scep.ParsePKIMessage(data, scep.WithCACerts(p.certificates))
	if err != nil {
		return errors.New("CertRep signature verification failed")
	}
	if reply.MessageType != scep.CertRep || reply.TransactionID != msg.TransactionID ||
		!bytes.Equal(reply.RecipientNonce, msg.SenderNonce) {
		return errors.New("CertRep transaction binding failed")
	}
	if !success {
		if reply.PKIStatus != scep.FAILURE {
			return errors.New("altered CSR unexpectedly accepted")
		}
		return nil
	}
	if reply.PKIStatus != scep.SUCCESS {
		return errors.New("valid CSR rejected")
	}
	if err := reply.DecryptPKIEnvelope(p.signer, p.key); err != nil {
		return errors.New("CertRep decryption failed")
	}
	cert := reply.Certificate
	if cert == nil || !bytes.Equal(cert.RawSubject, msg.CSR.RawSubject) ||
		!reflect.DeepEqual(cert.PublicKey, p.key.Public()) || cert.IsCA ||
		cert.KeyUsage != x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment ||
		!reflect.DeepEqual(cert.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}) {
		return errors.New("issued certificate constraints mismatch")
	}
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots: p.roots, Intermediates: p.intermediates,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return errors.New("issued certificate trust verification failed")
	}
	return nil
}

func run() error {
	pkcs7.ContentEncryptionAlgorithm = pkcs7.EncryptionAlgorithmAES256CBC
	var config input
	decoder := json.NewDecoder(io.LimitReader(os.Stdin, 8192))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return errors.New("invalid input JSON")
	}
	u, err := url.Parse(config.URL)
	if err != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
		(u.Scheme != "https" && !(u.Scheme == "http" && u.Hostname() == "127.0.0.1")) ||
		len(config.Challenge) != 43 || config.CommonName == "" {
		return errors.New("invalid test configuration")
	}
	root, err := os.ReadFile(config.RootFile)
	if err != nil {
		return errors.New("root read failed")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(root) {
		return errors.New("root parse failed")
	}
	p := &probe{config: config, roots: roots, intermediates: x509.NewCertPool(), client: &http.Client{
		Timeout:       30 * time.Second,
		Transport:     &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
	caData, err := p.request("GetCACert", nil)
	if err != nil {
		return err
	}
	p.certificates, err = scep.CACerts(caData)
	if err != nil || len(p.certificates) == 0 {
		return errors.New("CA response parse failed")
	}
	for _, cert := range p.certificates {
		p.intermediates.AddCert(cert)
	}
	for _, cert := range p.certificates {
		if _, err := cert.Verify(x509.VerifyOptions{
			Roots: roots, Intermediates: p.intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		}); err != nil {
			return errors.New("CA response trust verification failed")
		}
	}
	p.key, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return errors.New("key generation failed")
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic SCEP probe"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	signerDER, err := x509.CreateCertificate(rand.Reader, template, template, &p.key.PublicKey, p.key)
	if err != nil {
		return errors.New("request signer generation failed")
	}
	p.signer, err = x509.ParseCertificate(signerDER)
	if err != nil {
		return errors.New("request signer parse failed")
	}
	bad, err := p.message(config.CommonName + "-altered")
	if err != nil {
		return err
	}
	if err := p.exchange(bad, false); err != nil {
		return fmt.Errorf("before binding: %w", err)
	}
	valid, err := p.message(config.CommonName)
	if err != nil {
		return err
	}
	for i := 0; i < 2; i++ {
		if err := p.exchange(valid, true); err != nil {
			return fmt.Errorf("valid request or identical retry: %w", err)
		}
	}
	if err := p.exchange(bad, false); err != nil {
		return fmt.Errorf("after binding: %w", err)
	}
	fmt.Println(`{"issued":true,"identical_retry":true,"altered_subject_rejected_before_and_after_binding":true}`)
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
