package dns

import (
	"crypto/sha1"
)

// HashName hashes a string (label) according to RFC 5155. It returns the hashed string in uppercase.
func HashName(label Name, ha uint8, iter uint16, salt []byte) []byte {
	if ha != SHA1 {
		return nil
	}

	name := label.Canonical().ToWire()

	s := sha1.New()
	// k = 0
	s.Write(name)
	s.Write(salt)
	nsec3 := s.Sum(nil)

	// k > 0
	for k := uint16(0); k < iter; k++ {
		s.Reset()
		s.Write(nsec3)
		s.Write(salt)
		nsec3 = s.Sum(nsec3[:0])
	}

	return nsec3
}

// Cover returns true if a name is covered by the NSEC3 record.
func (rr *NSEC3) Cover(name Name) bool {
	nameHash := BFFromBytes(HashName(name, rr.Hash, rr.Iterations, rr.Salt.Raw()))
	owner := rr.Hdr.Name
	labels := owner.SplitRaw()
	if len(labels) < 2 {
		return false
	}
	ownerHash, err := BFFromBase32(string(labels[0]))
	if err != nil {
		return false
	}
	ownerZone, _ := NameFromLabels(labels[1:])
	if !IsSubDomain(ownerZone, name) { // name is outside owner zone
		return false
	}

	nextHash := rr.NextDomain

	// if empty interval found, try cover wildcard hashes so nameHash shouldn't match with ownerHash
	if ownerHash == nextHash && nameHash != ownerHash { // empty interval
		return true
	}
	if ownerHash.raw > nextHash.raw { // end of zone
		if nameHash.raw > ownerHash.raw { // covered since there is nothing after ownerHash
			return true
		}
		return nameHash.raw < nextHash.raw // if nameHash is before beginning of zone it is covered
	}
	if nameHash.raw < ownerHash.raw { // nameHash is before ownerHash, not covered
		return false
	}
	return nameHash.raw < nextHash.raw // if nameHash is before nextHash is it covered (between ownerHash and nextHash)
}

// Match returns true if a name matches the NSEC3 record
func (rr *NSEC3) Match(name Name) bool {
	nameHash := BFFromBytes(HashName(name, rr.Hash, rr.Iterations, rr.Salt.Raw()))
	owner := rr.Hdr.Name
	labels := owner.SplitRaw()
	if len(labels) < 2 {
		return false
	}
	ownerHash, err := BFFromBase32(string(labels[0]))
	if err != nil {
		return false
	}
	ownerZone, err := NameFromLabels(labels[1:])
	if err != nil {
		panic(err)
	}
	if !IsSubDomain(ownerZone, name) { // name is outside owner zone
		return false
	}
	return ownerHash == nameHash
}

// Match returns true if the given name is covered by the NSEC record
func (rr *NSEC) Cover(name Name) bool {
	switch Compare(rr.Hdr.Name, name) {
	default: // case 0:
		// equals to start => covers
		return true
	case 1:
		// start after name => no possible way for it to cover
		return false
	case -1:
		// have to check end
		switch Compare(name, rr.NextDomain) {
		default: // case 0:
			// name equals end, does not cover due to half open range [start, end)
			return false
		case -1:
			// name is before end, covers
			return true
		case 1:
			// after end? only covers for the case of [zone-last-record.zone.tld., zone.tld.]
			return Compare(rr.Hdr.Name, rr.NextDomain) == 1
		}
	}
}
