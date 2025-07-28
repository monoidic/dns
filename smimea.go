package dns

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
)

// Sign creates a SMIMEA record from an SSL certificate.
func (r *SMIMEA) Sign(usage, selector, matchingType int, cert *x509.Certificate) (err error) {
	r.Hdr.Rrtype = TypeSMIMEA
	r.Usage = uint8(usage)
	r.Selector = uint8(selector)
	r.MatchingType = uint8(matchingType)

	r.Certificate, err = CertificateToDANE(r.Selector, r.MatchingType, cert)
	return err
}

// Verify verifies a SMIMEA record against an SSL certificate. If it is OK
// a nil error is returned.
func (r *SMIMEA) Verify(cert *x509.Certificate) error {
	c, err := CertificateToDANE(r.Selector, r.MatchingType, cert)
	if err != nil {
		return err // Not also ErrSig?
	}
	if r.Certificate == c {
		return nil
	}
	return ErrSig // ErrSig, really?
}

// SMIMEAName returns the ownername of a SMIMEA resource record as per the
// format specified in RFC 'draft-ietf-dane-smime-12' Section 2 and 3
func SMIMEAName(email string, domain Name) (Name, error) {
	hasher := sha256.New()
	hasher.Write([]byte(email))

	// RFC Section 3: "The local-part is hashed using the SHA2-256
	// algorithm with the hash truncated to 28 octets and
	// represented in its hexadecimal representation to become the
	// left-most label in the prepared domain name"
	split := domain.SplitRaw()
	labels := make([]string, len(split)+2)
	labels[0] = hex.EncodeToString(hasher.Sum(nil)[:28])
	labels[1] = "_smimecert"
	copy(labels[2:], split)
	return NameFromLabels(labels)
}
