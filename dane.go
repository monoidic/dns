package dns

import (
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"errors"
)

// CertificateToDANE converts a certificate to a hex string as used in the TLSA or SMIMEA records.
func CertificateToDANE(selector, matchingType uint8, cert *x509.Certificate) (ByteField, error) {
	var data []byte
	var ret ByteField
	switch selector {
	case 0:
		data = cert.Raw
	case 1:
		data = cert.RawSubjectPublicKeyInfo
	default:
		return ret, errors.New("dns: bad MatchingType or Selector")
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
		return ret, errors.New("dns: bad MatchingType or Selector")
	}

	ret = BFFromBytes(data)
	return ret, nil
}
