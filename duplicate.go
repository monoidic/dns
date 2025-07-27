package dns

import "net/netip"

//go:generate go run duplicate_generate.go

// IsDuplicate checks of r1 and r2 are duplicates of each other, excluding the TTL.
// So this means the header data is equal *and* the RDATA is the same. Returns true
// if so, otherwise false. It's a protocol violation to have identical RRs in a message.
func IsDuplicate(r1, r2 RR) bool {
	if r1 == nil || r2 == nil {
		return r1 == r2
	}
	// Check whether the record header is identical.
	if !r1.Header().isDuplicate(r2.Header()) {
		return false
	}

	// Check whether the RDATA is identical.
	return r1.isDuplicate(r2)
}

func (r1 *RR_Header) isDuplicate(_r2 RR) bool {
	r2, ok := _r2.(*RR_Header)
	if !ok {
		return false
	}
	if r1.Class != r2.Class {
		return false
	}
	if r1.Rrtype != r2.Rrtype {
		return false
	}
	if !isDuplicateName(r1.Name, r2.Name) {
		return false
	}
	// ignore TTL
	return true
}

// isDuplicateName checks if the domain names s1 and s2 are equal.
func isDuplicateName(s1, s2 Name) bool {
	// funnily enough, the maximum label length is 0x3f, before 0x41 (A)
	// the only places where A-Z could occur would be within labels, so this will just work™
	return equal(s1.encoded, s2.encoded)
}

func isDuplicateGateway(gatewayType uint8, laddr, raddr netip.Addr, lhost, rhost Name) bool {
	switch gatewayType & 0x7f {
	case IPSECGatewayIPv4, IPSECGatewayIPv6:
		return laddr == raddr
	case IPSECGatewayHost:
		return isDuplicateName(lhost, rhost)
	default:
		return true
	}
}
