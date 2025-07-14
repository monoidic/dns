package dns

import (
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"errors"
)

// CertificateToDANE converts a certificate to a hex string as used in the TLSA or SMIMEA records.
func CertificateToDANE(selector, matchingType uint8, cert *x509.Certificate) (string, error) {
	var data []byte
	switch selector {
	case 0:
		data = cert.Raw
	case 1:
		data = cert.RawSubjectPublicKeyInfo
	default:
		return "", errors.New("dns: bad MatchingType or Selector")
	}

	switch matchingType {
	case 0:
	// nop
	case 1:
		h := sha256.New()
		h.Write(data)
		data = h.Sum(nil)
	case 2:
		h := sha512.New()
		h.Write(data)
		data = h.Sum(nil)
	default:
		return "", errors.New("dns: bad MatchingType or Selector")
	}

	return hex.EncodeToString(data), nil
}
