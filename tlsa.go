package dns

import (
	"crypto/x509"
	"net"
	"strconv"
)

// Sign creates a TLSA record from an SSL certificate.
func (r *TLSA) Sign(usage, selector, matchingType int, cert *x509.Certificate) (err error) {
	r.Hdr.Rrtype = TypeTLSA
	r.Usage = uint8(usage)
	r.Selector = uint8(selector)
	r.MatchingType = uint8(matchingType)

	r.Certificate, err = CertificateToDANE(r.Selector, r.MatchingType, cert)
	return err
}

// Verify verifies a TLSA record against an SSL certificate. If it is OK
// a nil error is returned.
func (r *TLSA) Verify(cert *x509.Certificate) error {
	c, err := CertificateToDANE(r.Selector, r.MatchingType, cert)
	if err != nil {
		return err // Not also ErrSig?
	}
	if r.Certificate != c {
		return ErrSig // ErrSig, really?
	}
	return nil
}

// TLSAName returns the ownername of a TLSA resource record as per the
// rules specified in RFC 6698, Section 3.
func TLSAName(name Name, service, network string) (Name, error) {
	p, err := net.LookupPort(network, service)
	if err != nil {
		return Name{}, err
	}
	split := name.SplitRaw()
	labels := make([]string, len(split)+2)
	labels[0] = "_" + strconv.Itoa(p)
	labels[1] = "_" + network
	copy(labels[2:], split)
	return NameFromLabels(labels)
}
