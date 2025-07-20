package dns

import (
	"net"
	"net/netip"
	"strconv"
	"strings"
)

const hexDigit = "0123456789abcdef"

// Everything is assumed in ClassINET.

// SetReply creates a reply message from a request message.
func (dns *Msg) SetReply(request *Msg) *Msg {
	dns.Id = request.Id
	dns.Response = true
	dns.Opcode = request.Opcode
	if dns.Opcode == OpcodeQuery {
		dns.RecursionDesired = request.RecursionDesired // Copy rd bit
		dns.CheckingDisabled = request.CheckingDisabled // Copy cd bit
	}
	dns.Rcode = RcodeSuccess
	if len(request.Question) > 0 {
		dns.Question = []Question{request.Question[0]}
	}
	return dns
}

// SetQuestion creates a question message, it sets the Question
// section, generates an Id and sets the RecursionDesired (RD)
// bit to true.
func (dns *Msg) SetQuestion(z Name, t uint16) *Msg {
	dns.Id = Id()
	dns.RecursionDesired = true
	dns.Question = make([]Question, 1)
	dns.Question[0] = Question{z, t, ClassINET}
	return dns
}

// SetNotify creates a notify message, it sets the Question
// section, generates an Id and sets the Authoritative (AA)
// bit to true.
func (dns *Msg) SetNotify(z Name) *Msg {
	dns.Opcode = OpcodeNotify
	dns.Authoritative = true
	dns.Id = Id()
	dns.Question = make([]Question, 1)
	dns.Question[0] = Question{z, TypeSOA, ClassINET}
	return dns
}

// SetRcode creates an error message suitable for the request.
func (dns *Msg) SetRcode(request *Msg, rcode int) *Msg {
	dns.SetReply(request)
	dns.Rcode = rcode
	return dns
}

// SetRcodeFormatError creates a message with FormError set.
func (dns *Msg) SetRcodeFormatError(request *Msg) *Msg {
	dns.Rcode = RcodeFormatError
	dns.Opcode = OpcodeQuery
	dns.Response = true
	dns.Authoritative = false
	dns.Id = request.Id
	return dns
}

// SetUpdate makes the message a dynamic update message. It
// sets the ZONE section to: z, TypeSOA, ClassINET.
func (dns *Msg) SetUpdate(z Name) *Msg {
	dns.Id = Id()
	dns.Response = false
	dns.Opcode = OpcodeUpdate
	dns.Compress = false // BIND9 cannot handle compression
	dns.Question = make([]Question, 1)
	dns.Question[0] = Question{z, TypeSOA, ClassINET}
	return dns
}

// SetIxfr creates message for requesting an IXFR.
func (dns *Msg) SetIxfr(z Name, serial uint32, ns, mbox Name) *Msg {
	dns.Id = Id()
	dns.Question = make([]Question, 1)
	dns.Ns = make([]RR, 1)
	s := new(SOA)
	s.Hdr = RR_Header{z, TypeSOA, ClassINET, defaultTtl, 0}
	s.Serial = serial
	s.Ns = ns
	s.Mbox = mbox
	dns.Question[0] = Question{z, TypeIXFR, ClassINET}
	dns.Ns[0] = s
	return dns
}

// SetAxfr creates message for requesting an AXFR.
func (dns *Msg) SetAxfr(z Name) *Msg {
	dns.Id = Id()
	dns.Question = make([]Question, 1)
	dns.Question[0] = Question{z, TypeAXFR, ClassINET}
	return dns
}

// SetTsig appends a TSIG RR to the message.
// This is only a skeleton TSIG RR that is added as the last RR in the
// additional section. The TSIG is calculated when the message is being send.
func (dns *Msg) SetTsig(z, algo Name, fudge uint16, timesigned int64) *Msg {
	t := new(TSIG)
	t.Hdr = RR_Header{z, TypeTSIG, ClassANY, 0, 0}
	t.Algorithm = algo
	t.Fudge = fudge
	t.TimeSigned = uint64(timesigned)
	t.OrigId = dns.Id
	dns.Extra = append(dns.Extra, t)
	return dns
}

// SetEdns0 appends a EDNS0 OPT RR to the message.
// TSIG should always the last RR in a message.
func (dns *Msg) SetEdns0(udpsize uint16, do bool) *Msg {
	e := new(OPT)
	e.Hdr.Name = mustParseName(".")
	e.Hdr.Rrtype = TypeOPT
	e.SetUDPSize(udpsize)
	if do {
		e.SetDo()
	}
	dns.Extra = append(dns.Extra, e)
	return dns
}

// IsTsig checks if the message has a TSIG record as the last record
// in the additional section. It returns the TSIG record found or nil.
func (dns *Msg) IsTsig() *TSIG {
	if len(dns.Extra) > 0 {
		if dns.Extra[len(dns.Extra)-1].Header().Rrtype == TypeTSIG {
			return dns.Extra[len(dns.Extra)-1].(*TSIG)
		}
	}
	return nil
}

// IsEdns0 checks if the message has a EDNS0 (OPT) record, any EDNS0
// record in the additional section will do. It returns the OPT record
// found or nil.
func (dns *Msg) IsEdns0() *OPT {
	// RFC 6891, Section 6.1.1 allows the OPT record to appear
	// anywhere in the additional record section, but it's usually at
	// the end so start there.
	for i := len(dns.Extra) - 1; i >= 0; i-- {
		if dns.Extra[i].Header().Rrtype == TypeOPT {
			return dns.Extra[i].(*OPT)
		}
	}
	return nil
}

// popEdns0 is like IsEdns0, but it removes the record from the message.
func (dns *Msg) popEdns0() *OPT {
	// RFC 6891, Section 6.1.1 allows the OPT record to appear
	// anywhere in the additional record section, but it's usually at
	// the end so start there.
	for i := len(dns.Extra) - 1; i >= 0; i-- {
		if dns.Extra[i].Header().Rrtype == TypeOPT {
			opt := dns.Extra[i].(*OPT)
			dns.Extra = append(dns.Extra[:i], dns.Extra[i+1:]...)
			return opt
		}
	}
	return nil
}

// IsDomainName checks if s is a valid domain name, it returns the number of
// labels and true, when a domain name is valid.  Note that non fully qualified
// domain name is considered valid, in this case the last label is counted in
// the number of labels.  When false is returned the number of labels is not
// defined.  Also note that this function is extremely liberal; almost any
// string is a valid domain name as the DNS is 8 bit protocol. It checks if each
// label fits in 63 characters and that the entire name will fit into the 255
// octet wire format limit.
func IsDomainName(s string) (labels int, ok bool) {
	if s == "." {
		// TODO(monoidic)
		// why pretend there's a label here and then not produce it with SplitDomainName?
		return 1, true
	}
	name, err := NameFromString(Fqdn(s))
	if err != nil {
		return 0, false
	}
	labels = len(name.SplitRaw())
	return labels, true
}

// IsSubDomain checks if child is indeed a child of the parent. If child and parent
// are the same domain true is returned as well.
func IsSubDomain(parent, child Name) bool {
	// Entire child is contained in parent
	return CompareDomainName(parent, child) == parent.CountLabel()
}

// IsFqdn checks if a domain name is fully qualified.
func IsFqdn(s string) bool {
	// Check for (and remove) a trailing dot, returning if there isn't one.
	if s == "" || s[len(s)-1] != '.' {
		return false
	}

	_, err := NameFromString(s)
	return err == nil
}

// IsRRset reports whether a set of RRs is a valid RRset as defined by RFC 2181.
// This means the RRs need to have the same type, name, and class.
func IsRRset(rrset []RR) bool {
	if len(rrset) == 0 {
		return false
	}

	baseH := rrset[0].Header()
	for _, rr := range rrset[1:] {
		curH := rr.Header()
		if curH.Rrtype != baseH.Rrtype || curH.Class != baseH.Class || curH.Name != baseH.Name {
			// Mismatch between the records, so this is not a valid rrset for
			// signing/verifying
			return false
		}
	}

	return true
}

// Fqdn return the fully qualified domain name from s.
// If s is already fully qualified, it behaves as the identity function.
func Fqdn(s string) string {
	if IsFqdn(s) {
		return s
	}
	return s + "."
}

// CanonicalName returns the domain name in canonical form. A name in canonical
// form is lowercase and fully qualified. Only US-ASCII letters are affected. See
// Section 6.2 in RFC 4034.
func CanonicalName(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'A' && r <= 'Z' {
			r += 'a' - 'A'
		}
		return r
	}, Fqdn(s))
}

// Copied from the official Go code.

// ReverseAddr returns the in-addr.arpa. or ip6.arpa. hostname of the IP
// address suitable for reverse DNS (PTR) record lookups or an error if it fails
// to parse the IP address.
func ReverseAddr(addr string) (arpa string, err error) {
	ip, err := netip.ParseAddr(addr)
	if err != nil {
		return "", &Error{err: "unrecognized address: " + addr}
	}
	ipSl := ip.AsSlice()
	if ip.Is4() {
		buf := make([]byte, 0, net.IPv4len*4+len("in-addr.arpa."))
		// Add it, in reverse, to the buffer
		for i := net.IPv4len - 1; i >= 0; i-- {
			buf = strconv.AppendInt(buf, int64(ipSl[i]), 10)
			buf = append(buf, '.')
		}
		// Append "in-addr.arpa." and return (buf already has the final .)
		buf = append(buf, "in-addr.arpa."...)
		return string(buf), nil
	}
	// Must be IPv6
	buf := make([]byte, 0, net.IPv6len*4+len("ip6.arpa."))
	// Add it, in reverse, to the buffer
	for i := net.IPv6len - 1; i >= 0; i-- {
		v := ipSl[i]
		buf = append(buf, hexDigit[v&0xF], '.', hexDigit[v>>4], '.')
	}
	// Append "ip6.arpa." and return (buf already has the final .)
	buf = append(buf, "ip6.arpa."...)
	return string(buf), nil
}

// String returns the string representation for the type t.
func (t Type) String() string {
	if t1, ok := TypeToString[uint16(t)]; ok {
		return t1
	}
	return "TYPE" + strconv.Itoa(int(t))
}

// String returns the string representation for the class c.
func (c Class) String() string {
	if s, ok := ClassToString[uint16(c)]; ok {
		// Only emit mnemonics when they are unambiguous, specially ANY is in both.
		if _, ok := StringToType[s]; !ok {
			return s
		}
	}
	return "CLASS" + strconv.Itoa(int(c))
}
