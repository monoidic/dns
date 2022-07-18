// Code generated by "go run duplicate_generate.go"; DO NOT EDIT.

package dns

// isDuplicate() functions

func (r1 *A) isDuplicate(_r2 RR) bool {
	r2, ok := _r2.(*A)
	if !ok {
		return false
	}
	if r1.A != r2.A {
		return false
	}
	return true
}

func (r1 *AAAA) isDuplicate(_r2 RR) bool {
	r2, ok := _r2.(*AAAA)
	if !ok {
		return false
	}
	if r1.AAAA != r2.AAAA {
		return false
	}
	return true
}

func (r1 *AFSDB) isDuplicate(_r2 RR) bool {
	r2, ok := _r2.(*AFSDB)
	if !ok {
		return false
	}
	if r1.Subtype != r2.Subtype {
		return false
	}
	if !isDuplicateName(r1.Hostname, r2.Hostname) {
		return false
	}
	return true
}

func (r1 *AMTRELAY) isDuplicate(_r2 RR) bool {
	r2, ok := _r2.(*AMTRELAY)
	if !ok {
		return false
	}
	if r1.Precedence != r2.Precedence {
		return false
	}
	if r1.GatewayType != r2.GatewayType {
		return false
	}
	switch r1.GatewayType {
	case IPSECGatewayIPv4, IPSECGatewayIPv6:
		if r1.GatewayAddr != r2.GatewayAddr {
			return false
		}
	case IPSECGatewayHost:
		if !isDuplicateName(r1.GatewayHost, r2.GatewayHost) {
			return false
		}
	}

	return true
}

func (r1 *ANY) isDuplicate(_r2 RR) bool {
	_, ok := _r2.(*ANY)
	if !ok {
		return false
	}
	return true
}

func (r1 *APL) isDuplicate(_r2 RR) bool {
	r2, ok := _r2.(*APL)
	if !ok {
		return false
	}
	if len(r1.Prefixes) != len(r2.Prefixes) {
		return false
	}
	for i := 0; i < len(r1.Prefixes); i++ {
		if !r1.Prefixes[i].equals(&r2.Prefixes[i]) {
			return false
		}
	}
	return true
}

func (r1 *AVC) isDuplicate(_r2 RR) bool {
	r2, ok := _r2.(*AVC)
	if !ok {
		return false
	}
	if len(r1.Txt) != len(r2.Txt) {
		return false
	}
	for i := 0; i < len(r1.Txt); i++ {
		if r1.Txt[i] != r2.Txt[i] {
			return false
		}
	}
	return true
}

func (r1 *CAA) isDuplicate(_r2 RR) bool {
	r2, ok := _r2.(*CAA)
	if !ok {
		return false
	}
	if r1.Flag != r2.Flag {
		return false
	}
	if r1.Tag != r2.Tag {
		return false
	}
	if r1.Value != r2.Value {
		return false
	}
	return true
}

func (r1 *CDNSKEY) isDuplicate(_r2 RR) bool {
	r2, ok := _r2.(*CDNSKEY)
	if !ok {
		return false
	}
	if r1.Flags != r2.Flags {
		return false
	}
	if r1.Protocol != r2.Protocol {
		return false
	}
	if r1.Algorithm != r2.Algorithm {
		return false
	}
	if r1.PublicKey != r2.PublicKey {
		return false
	}
	return true
}

func (r1 *CDS) isDuplicate(_r2 RR) bool {
	r2, ok := _r2.(*CDS)
	if !ok {
		return false
	}
	if r1.KeyTag != r2.KeyTag {
		return false
	}
	if r1.Algorithm != r2.Algorithm {
		return false
	}
	if r1.DigestType != r2.DigestType {
		return false
	}
	if r1.Digest != r2.Digest {
		return false
	}
	return true
}

func (r1 *CERT) isDuplicate(_r2 RR) bool {
	r2, ok := _r2.(*CERT)
	if !ok {
		return false
	}
	if r1.Type != r2.Type {
		return false
	}
	if r1.KeyTag != r2.KeyTag {
		return false
	}
	if r1.Algorithm != r2.Algorithm {
		return false
	}
	if r1.Certificate != r2.Certificate {
		return false
	}
	return true
}

func (r1 *CNAME) isDuplicate(_r2 RR) bool {
	r2, ok := _r2.(*CNAME)
	if !ok {
		return false
	}
	if !isDuplicateName(r1.Target, r2.Target) {
		return false
	}
	return true
}

func (r1 *CSYNC) isDuplicate(_r2 RR) bool {
	r2, ok := _r2.(*CSYNC)
	if !ok {
		return false
	}
	if r1.Serial != r2.Serial {
		return false
	}
	if r1.Flags != r2.Flags {
		return false
	}
	if len(r1.TypeBitMap) != len(r2.TypeBitMap) {
		return false
	}
	for i := 0; i < len(r1.TypeBitMap); i++ {
		if r1.TypeBitMap[i] != r2.TypeBitMap[i] {
			return false
		}
	}
	return true
}

func (r1 *DHCID) isDuplicate(_r2 RR) bool {
	r2, ok := _r2.(*DHCID)
	if !ok {
		return false
	}
	if r1.Digest != r2.Digest {
		return false
	}
	return true
}

func (r1 *DLV) isDuplicate(_r2 RR) bool {
	r2, ok := _r2.(*DLV)
	if !ok {
		return false
	}
	if r1.KeyTag != r2.KeyTag {
		return false
	}
	if r1.Algorithm != r2.Algorithm {
		return false
	}
	if r1.DigestType != r2.DigestType {
		return false
	}
	if r1.Digest != r2.Digest {
		return false
	}
	return true
}

func (r1 *DNAME) isDuplicate(_r2 RR) bool {
	r2, ok := _r2.(*DNAME)
	if !ok {
		return false
	}
	if !isDuplicateName(r1.Target, r2.Target) {
		return false
	}
	return true
}

func (r1 *DNSKEY) isDuplicate(_r2 RR) bool {
	r2, ok := _r2.(*DNSKEY)
	if !ok {
		return false
	}
	if r1.Flags != r2.Flags {
		return false
	}
	if r1.Protocol != r2.Protocol {
		return false
	}
	if r1.Algorithm != r2.Algorithm {
		return false
	}
	if r1.PublicKey != r2.PublicKey {
		return false
	}
	return true
}

func (r1 *DS) isDuplicate(_r2 RR) bool {
	r2, ok := _r2.(*DS)
	if !ok {
		return false
	}
	if r1.KeyTag != r2.KeyTag {
		return false
	}
	if r1.Algorithm != r2.Algorithm {
		return false
	}
	if r1.DigestType != r2.DigestType {
		return false
	}
	if r1.Digest != r2.Digest {
		return false
	}
	return true
}

func (r1 *EID) isDuplicate(_r2 RR) bool {
	r2, ok := _r2.(*EID)
	if !ok {
		return false
	}
	if r1.Endpoint != r2.Endpoint {
		return false
	}
	return true
}

func (r1 *EUI48) isDuplicate(_r2 RR) bool {
	r2, ok := _r2.(*EUI48)
	if !ok {
		return false
	}
	if r1.Address != r2.Address {
		return false
	}
	return true
}

func (r1 *EUI64) isDuplicate(_r2 RR) bool {
	r2, ok := _r2.(*EUI64)
	if !ok {
		return false
	}
	if r1.Address != r2.Address {
		return false
	}
	return true
}

func (r1 *GID) isDuplicate(_r2 RR) bool {
	r2, ok := _r2.(*GID)
	if !ok {
		return false
	}
	if r1.Gid != r2.Gid {
		return false
	}
	return true
}

func (r1 *GPOS) isDuplicate(_r2 RR) bool {
	r2, ok := _r2.(*GPOS)
	if !ok {
		return false
	}
	if r1.Longitude != r2.Longitude {
		return false
	}
	if r1.Latitude != r2.Latitude {
		return false
	}
	if r1.Altitude != r2.Altitude {
		return false
	}
	return true
}

func (r1 *HINFO) isDuplicate(_r2 RR) bool {
	r2, ok := _r2.(*HINFO)
	if !ok {
		return false
	}
	if r1.Cpu != r2.Cpu {
		return false
	}
	if r1.Os != r2.Os {
		return false
	}
	return true
}

func (r1 *HIP) isDuplicate(_r2 RR) bool {
	r2, ok := _r2.(*HIP)
	if !ok {
		return false
	}
	if r1.HitLength != r2.HitLength {
		return false
	}
	if r1.PublicKeyAlgorithm != r2.PublicKeyAlgorithm {
		return false
	}
	if r1.PublicKeyLength != r2.PublicKeyLength {
		return false
	}
	if r1.Hit != r2.Hit {
		return false
	}
	if r1.PublicKey != r2.PublicKey {
		return false
	}
	if len(r1.RendezvousServers) != len(r2.RendezvousServers) {
		return false
	}
	for i := 0; i < len(r1.RendezvousServers); i++ {
		if !isDuplicateName(r1.RendezvousServers[i], r2.RendezvousServers[i]) {
			return false
		}
	}
	return true
}

func (r1 *HTTPS) isDuplicate(_r2 RR) bool {
	r2, ok := _r2.(*HTTPS)
	if !ok {
		return false
	}
	if r1.Priority != r2.Priority {
		return false
	}
	if !isDuplicateName(r1.Target, r2.Target) {
		return false
	}
	if len(r1.Value) != len(r2.Value) {
		return false
	}
	if !areSVCBPairArraysEqual(r1.Value, r2.Value) {
		return false
	}
	return true
}

func (r1 *IPSECKEY) isDuplicate(_r2 RR) bool {
	r2, ok := _r2.(*IPSECKEY)
	if !ok {
		return false
	}
	if r1.Precedence != r2.Precedence {
		return false
	}
	if r1.GatewayType != r2.GatewayType {
		return false
	}
	if r1.Algorithm != r2.Algorithm {
		return false
	}
	switch r1.GatewayType {
	case IPSECGatewayIPv4, IPSECGatewayIPv6:
		if r1.GatewayAddr != r2.GatewayAddr {
			return false
		}
	case IPSECGatewayHost:
		if !isDuplicateName(r1.GatewayHost, r2.GatewayHost) {
			return false
		}
	}

	if r1.PublicKey != r2.PublicKey {
		return false
	}
	return true
}

func (r1 *KEY) isDuplicate(_r2 RR) bool {
	r2, ok := _r2.(*KEY)
	if !ok {
		return false
	}
	if r1.Flags != r2.Flags {
		return false
	}
	if r1.Protocol != r2.Protocol {
		return false
	}
	if r1.Algorithm != r2.Algorithm {
		return false
	}
	if r1.PublicKey != r2.PublicKey {
		return false
	}
	return true
}

func (r1 *KX) isDuplicate(_r2 RR) bool {
	r2, ok := _r2.(*KX)
	if !ok {
		return false
	}
	if r1.Preference != r2.Preference {
		return false
	}
	if !isDuplicateName(r1.Exchanger, r2.Exchanger) {
		return false
	}
	return true
}

func (r1 *L32) isDuplicate(_r2 RR) bool {
	r2, ok := _r2.(*L32)
	if !ok {
		return false
	}
	if r1.Preference != r2.Preference {
		return false
	}
	if r1.Locator32 != r2.Locator32 {
		return false
	}
	return true
}

func (r1 *L64) isDuplicate(_r2 RR) bool {
	r2, ok := _r2.(*L64)
	if !ok {
		return false
	}
	if r1.Preference != r2.Preference {
		return false
	}
	if r1.Locator64 != r2.Locator64 {
		return false
	}
	return true
}

func (r1 *LOC) isDuplicate(_r2 RR) bool {
	r2, ok := _r2.(*LOC)
	if !ok {
		return false
	}
	if r1.Version != r2.Version {
		return false
	}
	if r1.Size != r2.Size {
		return false
	}
	if r1.HorizPre != r2.HorizPre {
		return false
	}
	if r1.VertPre != r2.VertPre {
		return false
	}
	if r1.Latitude != r2.Latitude {
		return false
	}
	if r1.Longitude != r2.Longitude {
		return false
	}
	if r1.Altitude != r2.Altitude {
		return false
	}
	return true
}

func (r1 *LP) isDuplicate(_r2 RR) bool {
	r2, ok := _r2.(*LP)
	if !ok {
		return false
	}
	if r1.Preference != r2.Preference {
		return false
	}
	if !isDuplicateName(r1.Fqdn, r2.Fqdn) {
		return false
	}
	return true
}

func (r1 *MB) isDuplicate(_r2 RR) bool {
	r2, ok := _r2.(*MB)
	if !ok {
		return false
	}
	if !isDuplicateName(r1.Mb, r2.Mb) {
		return false
	}
	return true
}

func (r1 *MD) isDuplicate(_r2 RR) bool {
	r2, ok := _r2.(*MD)
	if !ok {
		return false
	}
	if !isDuplicateName(r1.Md, r2.Md) {
		return false
	}
	return true
}

func (r1 *MF) isDuplicate(_r2 RR) bool {
	r2, ok := _r2.(*MF)
	if !ok {
		return false
	}
	if !isDuplicateName(r1.Mf, r2.Mf) {
		return false
	}
	return true
}

func (r1 *MG) isDuplicate(_r2 RR) bool {
	r2, ok := _r2.(*MG)
	if !ok {
		return false
	}
	if !isDuplicateName(r1.Mg, r2.Mg) {
		return false
	}
	return true
}

func (r1 *MINFO) isDuplicate(_r2 RR) bool {
	r2, ok := _r2.(*MINFO)
	if !ok {
		return false
	}
	if !isDuplicateName(r1.Rmail, r2.Rmail) {
		return false
	}
	if !isDuplicateName(r1.Email, r2.Email) {
		return false
	}
	return true
}

func (r1 *MR) isDuplicate(_r2 RR) bool {
	r2, ok := _r2.(*MR)
	if !ok {
		return false
	}
	if !isDuplicateName(r1.Mr, r2.Mr) {
		return false
	}
	return true
}

func (r1 *MX) isDuplicate(_r2 RR) bool {
	r2, ok := _r2.(*MX)
	if !ok {
		return false
	}
	if r1.Preference != r2.Preference {
		return false
	}
	if !isDuplicateName(r1.Mx, r2.Mx) {
		return false
	}
	return true
}

func (r1 *NAPTR) isDuplicate(_r2 RR) bool {
	r2, ok := _r2.(*NAPTR)
	if !ok {
		return false
	}
	if r1.Order != r2.Order {
		return false
	}
	if r1.Preference != r2.Preference {
		return false
	}
	if r1.Flags != r2.Flags {
		return false
	}
	if r1.Service != r2.Service {
		return false
	}
	if r1.Regexp != r2.Regexp {
		return false
	}
	if !isDuplicateName(r1.Replacement, r2.Replacement) {
		return false
	}
	return true
}

func (r1 *NID) isDuplicate(_r2 RR) bool {
	r2, ok := _r2.(*NID)
	if !ok {
		return false
	}
	if r1.Preference != r2.Preference {
		return false
	}
	if r1.NodeID != r2.NodeID {
		return false
	}
	return true
}

func (r1 *NIMLOC) isDuplicate(_r2 RR) bool {
	r2, ok := _r2.(*NIMLOC)
	if !ok {
		return false
	}
	if r1.Locator != r2.Locator {
		return false
	}
	return true
}

func (r1 *NINFO) isDuplicate(_r2 RR) bool {
	r2, ok := _r2.(*NINFO)
	if !ok {
		return false
	}
	if len(r1.ZSData) != len(r2.ZSData) {
		return false
	}
	for i := 0; i < len(r1.ZSData); i++ {
		if r1.ZSData[i] != r2.ZSData[i] {
			return false
		}
	}
	return true
}

func (r1 *NS) isDuplicate(_r2 RR) bool {
	r2, ok := _r2.(*NS)
	if !ok {
		return false
	}
	if !isDuplicateName(r1.Ns, r2.Ns) {
		return false
	}
	return true
}

func (r1 *NSAPPTR) isDuplicate(_r2 RR) bool {
	r2, ok := _r2.(*NSAPPTR)
	if !ok {
		return false
	}
	if !isDuplicateName(r1.Ptr, r2.Ptr) {
		return false
	}
	return true
}

func (r1 *NSEC) isDuplicate(_r2 RR) bool {
	r2, ok := _r2.(*NSEC)
	if !ok {
		return false
	}
	if !isDuplicateName(r1.NextDomain, r2.NextDomain) {
		return false
	}
	if len(r1.TypeBitMap) != len(r2.TypeBitMap) {
		return false
	}
	for i := 0; i < len(r1.TypeBitMap); i++ {
		if r1.TypeBitMap[i] != r2.TypeBitMap[i] {
			return false
		}
	}
	return true
}

func (r1 *NSEC3) isDuplicate(_r2 RR) bool {
	r2, ok := _r2.(*NSEC3)
	if !ok {
		return false
	}
	if r1.Hash != r2.Hash {
		return false
	}
	if r1.Flags != r2.Flags {
		return false
	}
	if r1.Iterations != r2.Iterations {
		return false
	}
	if r1.SaltLength != r2.SaltLength {
		return false
	}
	if r1.Salt != r2.Salt {
		return false
	}
	if r1.HashLength != r2.HashLength {
		return false
	}
	if r1.NextDomain != r2.NextDomain {
		return false
	}
	if len(r1.TypeBitMap) != len(r2.TypeBitMap) {
		return false
	}
	for i := 0; i < len(r1.TypeBitMap); i++ {
		if r1.TypeBitMap[i] != r2.TypeBitMap[i] {
			return false
		}
	}
	return true
}

func (r1 *NSEC3PARAM) isDuplicate(_r2 RR) bool {
	r2, ok := _r2.(*NSEC3PARAM)
	if !ok {
		return false
	}
	if r1.Hash != r2.Hash {
		return false
	}
	if r1.Flags != r2.Flags {
		return false
	}
	if r1.Iterations != r2.Iterations {
		return false
	}
	if r1.SaltLength != r2.SaltLength {
		return false
	}
	if r1.Salt != r2.Salt {
		return false
	}
	return true
}

func (r1 *NULL) isDuplicate(_r2 RR) bool {
	r2, ok := _r2.(*NULL)
	if !ok {
		return false
	}
	if r1.Data != r2.Data {
		return false
	}
	return true
}

func (r1 *OPENPGPKEY) isDuplicate(_r2 RR) bool {
	r2, ok := _r2.(*OPENPGPKEY)
	if !ok {
		return false
	}
	if r1.PublicKey != r2.PublicKey {
		return false
	}
	return true
}

func (r1 *PTR) isDuplicate(_r2 RR) bool {
	r2, ok := _r2.(*PTR)
	if !ok {
		return false
	}
	if !isDuplicateName(r1.Ptr, r2.Ptr) {
		return false
	}
	return true
}

func (r1 *PX) isDuplicate(_r2 RR) bool {
	r2, ok := _r2.(*PX)
	if !ok {
		return false
	}
	if r1.Preference != r2.Preference {
		return false
	}
	if !isDuplicateName(r1.Map822, r2.Map822) {
		return false
	}
	if !isDuplicateName(r1.Mapx400, r2.Mapx400) {
		return false
	}
	return true
}

func (r1 *RFC3597) isDuplicate(_r2 RR) bool {
	r2, ok := _r2.(*RFC3597)
	if !ok {
		return false
	}
	if r1.Rdata != r2.Rdata {
		return false
	}
	return true
}

func (r1 *RKEY) isDuplicate(_r2 RR) bool {
	r2, ok := _r2.(*RKEY)
	if !ok {
		return false
	}
	if r1.Flags != r2.Flags {
		return false
	}
	if r1.Protocol != r2.Protocol {
		return false
	}
	if r1.Algorithm != r2.Algorithm {
		return false
	}
	if r1.PublicKey != r2.PublicKey {
		return false
	}
	return true
}

func (r1 *RP) isDuplicate(_r2 RR) bool {
	r2, ok := _r2.(*RP)
	if !ok {
		return false
	}
	if !isDuplicateName(r1.Mbox, r2.Mbox) {
		return false
	}
	if !isDuplicateName(r1.Txt, r2.Txt) {
		return false
	}
	return true
}

func (r1 *RRSIG) isDuplicate(_r2 RR) bool {
	r2, ok := _r2.(*RRSIG)
	if !ok {
		return false
	}
	if r1.TypeCovered != r2.TypeCovered {
		return false
	}
	if r1.Algorithm != r2.Algorithm {
		return false
	}
	if r1.Labels != r2.Labels {
		return false
	}
	if r1.OrigTtl != r2.OrigTtl {
		return false
	}
	if r1.Expiration != r2.Expiration {
		return false
	}
	if r1.Inception != r2.Inception {
		return false
	}
	if r1.KeyTag != r2.KeyTag {
		return false
	}
	if !isDuplicateName(r1.SignerName, r2.SignerName) {
		return false
	}
	if r1.Signature != r2.Signature {
		return false
	}
	return true
}

func (r1 *RT) isDuplicate(_r2 RR) bool {
	r2, ok := _r2.(*RT)
	if !ok {
		return false
	}
	if r1.Preference != r2.Preference {
		return false
	}
	if !isDuplicateName(r1.Host, r2.Host) {
		return false
	}
	return true
}

func (r1 *SIG) isDuplicate(_r2 RR) bool {
	r2, ok := _r2.(*SIG)
	if !ok {
		return false
	}
	if r1.TypeCovered != r2.TypeCovered {
		return false
	}
	if r1.Algorithm != r2.Algorithm {
		return false
	}
	if r1.Labels != r2.Labels {
		return false
	}
	if r1.OrigTtl != r2.OrigTtl {
		return false
	}
	if r1.Expiration != r2.Expiration {
		return false
	}
	if r1.Inception != r2.Inception {
		return false
	}
	if r1.KeyTag != r2.KeyTag {
		return false
	}
	if !isDuplicateName(r1.SignerName, r2.SignerName) {
		return false
	}
	if r1.Signature != r2.Signature {
		return false
	}
	return true
}

func (r1 *SMIMEA) isDuplicate(_r2 RR) bool {
	r2, ok := _r2.(*SMIMEA)
	if !ok {
		return false
	}
	if r1.Usage != r2.Usage {
		return false
	}
	if r1.Selector != r2.Selector {
		return false
	}
	if r1.MatchingType != r2.MatchingType {
		return false
	}
	if r1.Certificate != r2.Certificate {
		return false
	}
	return true
}

func (r1 *SOA) isDuplicate(_r2 RR) bool {
	r2, ok := _r2.(*SOA)
	if !ok {
		return false
	}
	if !isDuplicateName(r1.Ns, r2.Ns) {
		return false
	}
	if !isDuplicateName(r1.Mbox, r2.Mbox) {
		return false
	}
	if r1.Serial != r2.Serial {
		return false
	}
	if r1.Refresh != r2.Refresh {
		return false
	}
	if r1.Retry != r2.Retry {
		return false
	}
	if r1.Expire != r2.Expire {
		return false
	}
	if r1.Minttl != r2.Minttl {
		return false
	}
	return true
}

func (r1 *SPF) isDuplicate(_r2 RR) bool {
	r2, ok := _r2.(*SPF)
	if !ok {
		return false
	}
	if len(r1.Txt) != len(r2.Txt) {
		return false
	}
	for i := 0; i < len(r1.Txt); i++ {
		if r1.Txt[i] != r2.Txt[i] {
			return false
		}
	}
	return true
}

func (r1 *SRV) isDuplicate(_r2 RR) bool {
	r2, ok := _r2.(*SRV)
	if !ok {
		return false
	}
	if r1.Priority != r2.Priority {
		return false
	}
	if r1.Weight != r2.Weight {
		return false
	}
	if r1.Port != r2.Port {
		return false
	}
	if !isDuplicateName(r1.Target, r2.Target) {
		return false
	}
	return true
}

func (r1 *SSHFP) isDuplicate(_r2 RR) bool {
	r2, ok := _r2.(*SSHFP)
	if !ok {
		return false
	}
	if r1.Algorithm != r2.Algorithm {
		return false
	}
	if r1.Type != r2.Type {
		return false
	}
	if r1.FingerPrint != r2.FingerPrint {
		return false
	}
	return true
}

func (r1 *SVCB) isDuplicate(_r2 RR) bool {
	r2, ok := _r2.(*SVCB)
	if !ok {
		return false
	}
	if r1.Priority != r2.Priority {
		return false
	}
	if !isDuplicateName(r1.Target, r2.Target) {
		return false
	}
	if len(r1.Value) != len(r2.Value) {
		return false
	}
	if !areSVCBPairArraysEqual(r1.Value, r2.Value) {
		return false
	}
	return true
}

func (r1 *TA) isDuplicate(_r2 RR) bool {
	r2, ok := _r2.(*TA)
	if !ok {
		return false
	}
	if r1.KeyTag != r2.KeyTag {
		return false
	}
	if r1.Algorithm != r2.Algorithm {
		return false
	}
	if r1.DigestType != r2.DigestType {
		return false
	}
	if r1.Digest != r2.Digest {
		return false
	}
	return true
}

func (r1 *TALINK) isDuplicate(_r2 RR) bool {
	r2, ok := _r2.(*TALINK)
	if !ok {
		return false
	}
	if !isDuplicateName(r1.PreviousName, r2.PreviousName) {
		return false
	}
	if !isDuplicateName(r1.NextName, r2.NextName) {
		return false
	}
	return true
}

func (r1 *TKEY) isDuplicate(_r2 RR) bool {
	r2, ok := _r2.(*TKEY)
	if !ok {
		return false
	}
	if !isDuplicateName(r1.Algorithm, r2.Algorithm) {
		return false
	}
	if r1.Inception != r2.Inception {
		return false
	}
	if r1.Expiration != r2.Expiration {
		return false
	}
	if r1.Mode != r2.Mode {
		return false
	}
	if r1.Error != r2.Error {
		return false
	}
	if r1.KeySize != r2.KeySize {
		return false
	}
	if r1.Key != r2.Key {
		return false
	}
	if r1.OtherLen != r2.OtherLen {
		return false
	}
	if r1.OtherData != r2.OtherData {
		return false
	}
	return true
}

func (r1 *TLSA) isDuplicate(_r2 RR) bool {
	r2, ok := _r2.(*TLSA)
	if !ok {
		return false
	}
	if r1.Usage != r2.Usage {
		return false
	}
	if r1.Selector != r2.Selector {
		return false
	}
	if r1.MatchingType != r2.MatchingType {
		return false
	}
	if r1.Certificate != r2.Certificate {
		return false
	}
	return true
}

func (r1 *TSIG) isDuplicate(_r2 RR) bool {
	r2, ok := _r2.(*TSIG)
	if !ok {
		return false
	}
	if !isDuplicateName(r1.Algorithm, r2.Algorithm) {
		return false
	}
	if r1.TimeSigned != r2.TimeSigned {
		return false
	}
	if r1.Fudge != r2.Fudge {
		return false
	}
	if r1.MACSize != r2.MACSize {
		return false
	}
	if r1.MAC != r2.MAC {
		return false
	}
	if r1.OrigId != r2.OrigId {
		return false
	}
	if r1.Error != r2.Error {
		return false
	}
	if r1.OtherLen != r2.OtherLen {
		return false
	}
	if r1.OtherData != r2.OtherData {
		return false
	}
	return true
}

func (r1 *TXT) isDuplicate(_r2 RR) bool {
	r2, ok := _r2.(*TXT)
	if !ok {
		return false
	}
	if len(r1.Txt) != len(r2.Txt) {
		return false
	}
	for i := 0; i < len(r1.Txt); i++ {
		if r1.Txt[i] != r2.Txt[i] {
			return false
		}
	}
	return true
}

func (r1 *UID) isDuplicate(_r2 RR) bool {
	r2, ok := _r2.(*UID)
	if !ok {
		return false
	}
	if r1.Uid != r2.Uid {
		return false
	}
	return true
}

func (r1 *UINFO) isDuplicate(_r2 RR) bool {
	r2, ok := _r2.(*UINFO)
	if !ok {
		return false
	}
	if r1.Uinfo != r2.Uinfo {
		return false
	}
	return true
}

func (r1 *URI) isDuplicate(_r2 RR) bool {
	r2, ok := _r2.(*URI)
	if !ok {
		return false
	}
	if r1.Priority != r2.Priority {
		return false
	}
	if r1.Weight != r2.Weight {
		return false
	}
	if r1.Target != r2.Target {
		return false
	}
	return true
}

func (r1 *X25) isDuplicate(_r2 RR) bool {
	r2, ok := _r2.(*X25)
	if !ok {
		return false
	}
	if r1.PSDNAddress != r2.PSDNAddress {
		return false
	}
	return true
}

func (r1 *ZONEMD) isDuplicate(_r2 RR) bool {
	r2, ok := _r2.(*ZONEMD)
	if !ok {
		return false
	}
	if r1.Serial != r2.Serial {
		return false
	}
	if r1.Scheme != r2.Scheme {
		return false
	}
	if r1.Hash != r2.Hash {
		return false
	}
	if r1.Digest != r2.Digest {
		return false
	}
	return true
}
