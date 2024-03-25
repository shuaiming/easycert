package easycert

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"strings"
	"time"
)

func publicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	case ed25519.PrivateKey:
		return k.Public().(ed25519.PublicKey)
	default:
		return nil
	}
}

// CreateCert create cert
func CreateCert(
	host string,
	ecdsaCurve string,
	ed25519Key bool,
	rsaBits int,
	validFrom string,
	validFor time.Duration,
	isCA bool,
	pkixName pkix.Name,
	key string,
	cert string) error {

	if len(host) == 0 {
		return errors.New("invalid host")
	}

	var priv interface{}
	var err error

	switch ecdsaCurve {
	case "":
		if ed25519Key {
			_, priv, err = ed25519.GenerateKey(rand.Reader)
		} else {
			priv, err = rsa.GenerateKey(rand.Reader, rsaBits)
		}
	case "P224":
		priv, err = ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	case "P256":
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "P384":
		priv, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "P521":
		priv, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	default:
		err = errors.New("unknown ecdsaCurve")
	}

	if err != nil {
		return err
	}

	var notBefore time.Time
	if len(validFrom) == 0 {
		notBefore = time.Now()
	} else {
		notBefore, err = time.Parse("Jan 2 15:04:05 2006", validFrom)
		if err != nil {
			return err
		}
	}

	notAfter := notBefore.Add(validFor)

	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return err
	}

	tp := x509.Certificate{
		Subject:   pkixName,
		NotBefore: notBefore,
		NotAfter:  notAfter,
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,

		SerialNumber: serialNumber,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},

		BasicConstraintsValid: true,
	}

	hosts := strings.Split(host, ",")
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tp.IPAddresses = append(tp.IPAddresses, ip)
		} else {
			tp.DNSNames = append(tp.DNSNames, h)
		}
	}

	if isCA {
		tp.IsCA = true
		tp.KeyUsage |= x509.KeyUsageCertSign
	}

	pub := publicKey(priv)
	derBytes, err := x509.CreateCertificate(rand.Reader, &tp, &tp, pub, priv)
	if err != nil {
		return err
	}

	certOut, err := os.Create(cert)
	if err != nil {
		return err
	}

	pemCert := pem.Block{Type: "CERTIFICATE", Bytes: derBytes}
	if err := pem.Encode(certOut, &pemCert); err != nil {
		return err
	}

	if err := certOut.Close(); err != nil {
		return err
	}

	keyOut, err := os.OpenFile(key, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}

	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return err
	}

	pemPrivKey := pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}
	if err := pem.Encode(keyOut, &pemPrivKey); err != nil {
		return err
	}

	if err := keyOut.Close(); err != nil {
		return err
	}

	return nil
}
