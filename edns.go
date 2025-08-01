package dns

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// EDNS0 Option codes.
const (
	EDNS0LLQ          = 0x1     // long lived queries: http://tools.ietf.org/html/draft-sekar-dns-llq-01
	EDNS0UL           = 0x2     // update lease draft: http://files.dns-sd.org/draft-sekar-dns-ul.txt
	EDNS0NSID         = 0x3     // nsid (See RFC 5001)
	EDNS0ESU          = 0x4     // ENUM Source-URI draft: https://datatracker.ietf.org/doc/html/draft-kaplan-enum-source-uri-00
	EDNS0DAU          = 0x5     // DNSSEC Algorithm Understood
	EDNS0DHU          = 0x6     // DS Hash Understood
	EDNS0N3U          = 0x7     // NSEC3 Hash Understood
	EDNS0SUBNET       = 0x8     // client-subnet (See RFC 7871)
	EDNS0EXPIRE       = 0x9     // EDNS0 expire
	EDNS0COOKIE       = 0xa     // EDNS0 Cookie
	EDNS0TCPKEEPALIVE = 0xb     // EDNS0 tcp keep alive (See RFC 7828)
	EDNS0PADDING      = 0xc     // EDNS0 padding (See RFC 7830)
	EDNS0EDE          = 0xf     // EDNS0 extended DNS errors (See RFC 8914)
	EDNS0LOCALSTART   = 0xFDE9  // Beginning of range reserved for local/experimental use (See RFC 6891)
	EDNS0LOCALEND     = 0xFFFE  // End of range reserved for local/experimental use (See RFC 6891)
	_DO               = 1 << 15 // DNSSEC OK
	_CO               = 1 << 14 // Compact Answers OK
)

// makeDataOpt is used to unpack the EDNS0 option(s) from a message.
func makeDataOpt(code uint16) EDNS0 {
	// All the EDNS0.* constants above need to be in this switch.
	switch code {
	case EDNS0LLQ:
		return new(EDNS0_LLQ)
	case EDNS0UL:
		return new(EDNS0_UL)
	case EDNS0NSID:
		return new(EDNS0_NSID)
	case EDNS0DAU:
		return new(EDNS0_DAU)
	case EDNS0DHU:
		return new(EDNS0_DHU)
	case EDNS0N3U:
		return new(EDNS0_N3U)
	case EDNS0SUBNET:
		return new(EDNS0_SUBNET)
	case EDNS0EXPIRE:
		return new(EDNS0_EXPIRE)
	case EDNS0COOKIE:
		return new(EDNS0_COOKIE)
	case EDNS0TCPKEEPALIVE:
		return new(EDNS0_TCP_KEEPALIVE)
	case EDNS0PADDING:
		return new(EDNS0_PADDING)
	case EDNS0EDE:
		return new(EDNS0_EDE)
	case EDNS0ESU:
		return new(EDNS0_ESU)
	default:
		e := new(EDNS0_LOCAL)
		e.Code = code
		return e
	}
}

// OPT is the EDNS0 RR appended to messages to convey extra (meta) information. See RFC 6891.
type OPT struct {
	Hdr    RR_Header
	Option []EDNS0 `dns:"opt"`
}

func (rr *OPT) String() string {
	var s strings.Builder
	s.WriteString("\n;; OPT PSEUDOSECTION:\n; EDNS: version ")
	s.WriteString(strconv.Itoa(int(rr.Version())))
	s.WriteString("; flags:")
	if rr.Do() {
		s.WriteString(" do")
		if rr.Co() {
			s.WriteString(", co")
		}
	}
	s.WriteString("; ")
	if rr.Hdr.Ttl&0x7FFF != 0 {
		s.WriteString(fmt.Sprintf("MBZ: 0x%04x, ", rr.Hdr.Ttl&0x7FFF))
	}
	s.WriteString("udp: ")
	s.WriteString(strconv.Itoa(int(rr.UDPSize())))

	for _, o := range rr.Option {
		switch o.(type) {
		case *EDNS0_NSID:
			s.WriteString("\n; NSID ")
			s.WriteString(o.String())
			h, e := o.pack()
			if e == nil {
				var r string
				for _, c := range h {
					r += "(" + string(c) + ")"
				}
				s.WriteString("  ")
				s.WriteString(r)
			}
		case *EDNS0_SUBNET:
			s.WriteString("\n; SUBNET: ")
		case *EDNS0_COOKIE:
			s.WriteString("\n; COOKIE: ")
		case *EDNS0_EXPIRE:
			s.WriteString("\n; EXPIRE: ")
		case *EDNS0_TCP_KEEPALIVE:
			s.WriteString("\n; KEEPALIVE: ")
		case *EDNS0_UL:
			s.WriteString("\n; UPDATE LEASE: ")
		case *EDNS0_LLQ:
			s.WriteString("\n; LONG LIVED QUERIES: ")
		case *EDNS0_DAU:
			s.WriteString("\n; DNSSEC ALGORITHM UNDERSTOOD: ")
		case *EDNS0_DHU:
			s.WriteString("\n; DS HASH UNDERSTOOD: ")
		case *EDNS0_N3U:
			s.WriteString("\n; NSEC3 HASH UNDERSTOOD: ")
		case *EDNS0_LOCAL:
			s.WriteString("\n; LOCAL OPT: ")
		case *EDNS0_PADDING:
			s.WriteString("\n; PADDING: ")
		case *EDNS0_EDE:
			s.WriteString("\n; EDE: ")
		case *EDNS0_ESU:
			s.WriteString("\n; ESU: ")
		default:
			return "unexpected EDNS0"
		}
		s.WriteString(o.String())
	}
	return s.String()
}

func (rr *OPT) len(off int, compression map[Name]struct{}) int {
	l := rr.Hdr.len(off, compression)
	for _, o := range rr.Option {
		l += 4 // Account for 2-byte option code and 2-byte option length.
		lo, _ := o.pack()
		l += len(lo)
	}
	return l
}

func (*OPT) parse(c *zlexer, origin Name) *ParseError {
	return &ParseError{err: "OPT records do not have a presentation format"}
}

func (rr *OPT) isDuplicate(r2 RR) bool { return false }

// Version returns the EDNS version used. Only zero is defined.
func (rr *OPT) Version() uint8 {
	return uint8(rr.Hdr.Ttl & 0x00FF0000 >> 16)
}

// SetVersion sets the version of EDNS. This is usually zero.
func (rr *OPT) SetVersion(v uint8) {
	rr.Hdr.Ttl = rr.Hdr.Ttl&0xFF00FFFF | uint32(v)<<16
}

// ExtendedRcode returns the EDNS extended RCODE field (the upper 8 bits of the TTL).
func (rr *OPT) ExtendedRcode() int {
	return int(rr.Hdr.Ttl&0xFF000000>>24) << 4
}

// SetExtendedRcode sets the EDNS extended RCODE field.
//
// If the RCODE is not an extended RCODE, will reset the extended RCODE field to 0.
func (rr *OPT) SetExtendedRcode(v uint16) {
	rr.Hdr.Ttl = rr.Hdr.Ttl&0x00FFFFFF | uint32(v>>4)<<24
}

// UDPSize returns the UDP buffer size.
func (rr *OPT) UDPSize() uint16 {
	return uint16(rr.Hdr.Class)
}

// SetUDPSize sets the UDP buffer size.
func (rr *OPT) SetUDPSize(size uint16) {
	rr.Hdr.Class = Class(size)
}

// Do returns the value of the DO (DNSSEC OK) bit.
func (rr *OPT) Do() bool {
	return rr.Hdr.Ttl&_DO == _DO
}

// SetDo sets the DO (DNSSEC OK) bit.
// If we pass an argument, set the DO bit to that value.
// It is possible to pass 2 or more arguments, but they will be ignored.
func (rr *OPT) SetDo(do ...bool) {
	if len(do) == 1 && !do[0] {
		rr.Hdr.Ttl &^= _DO
	} else {
		rr.Hdr.Ttl |= _DO
	}
}

// Co returns the value of the CO (Compact Answers OK) bit.
func (rr *OPT) Co() bool {
	return rr.Hdr.Ttl&_CO == _CO
}

// SetCo sets the CO (Compact Answers OK) bit.
// If we pass an argument, set the CO bit to that value.
// It is possible to pass 2 or more arguments, but they will be ignored.
func (rr *OPT) SetCo(co ...bool) {
	if len(co) == 1 && !co[0] {
		rr.Hdr.Ttl &^= _CO
	} else {
		rr.Hdr.Ttl |= _CO
	}
}

// Z returns the Z part of the OPT RR as a uint16 with only the 14 least significant bits used.
func (rr *OPT) Z() uint16 {
	return uint16(rr.Hdr.Ttl & 0x3FFF)
}

// SetZ sets the Z part of the OPT RR, note only the 14 least significant bits of z are used.
func (rr *OPT) SetZ(z uint16) {
	rr.Hdr.Ttl = rr.Hdr.Ttl&^0x3FFF | uint32(z&0x3FFF)
}

// EDNS0 defines an EDNS0 Option. An OPT RR can have multiple options appended to it.
type EDNS0 interface {
	// Option returns the option code for the option.
	Option() uint16
	// pack returns the bytes of the option data.
	pack() ([]byte, error)
	// unpack sets the data as found in the buffer. Is also sets
	// the length of the slice as the length of the option data.
	unpack([]byte) error
	// String returns the string representation of the option.
	String() string
	// copy returns a deep-copy of the option.
	copy() EDNS0
}

// EDNS0_NSID option is used to retrieve a nameserver
// identifier. When sending a request Nsid must be set to the empty string
// The identifier is an opaque string encoded as hex.
// Basic use pattern for creating an nsid option:
//
//	o := new(dns.OPT)
//	o.Hdr.Name = "."
//	o.Hdr.Rrtype = dns.TypeOPT
//	e := new(dns.EDNS0_NSID)
//	e.Code = dns.EDNS0NSID
//	e.Nsid = "AA"
//	o.Option = append(o.Option, e)
type EDNS0_NSID struct {
	Code uint16    // always EDNS0NSID
	Nsid ByteField `dns:"hex"`
}

func (e *EDNS0_NSID) pack() ([]byte, error) {
	return e.Nsid.Raw(), nil
}

// Option implements the EDNS0 interface.
func (e *EDNS0_NSID) Option() uint16        { return EDNS0NSID } // Option returns the option code.
func (e *EDNS0_NSID) unpack(b []byte) error { e.Nsid = BFFromBytes(b); return nil }
func (e *EDNS0_NSID) String() string        { return e.Nsid.Hex() }
func (e *EDNS0_NSID) copy() EDNS0           { return &EDNS0_NSID{e.Code, e.Nsid} }

// EDNS0_SUBNET is the subnet option that is used to give the remote nameserver
// an idea of where the client lives. See RFC 7871. It can then give back a different
// answer depending on the location or network topology.
// Basic use pattern for creating an subnet option:
//
//	o := new(dns.OPT)
//	o.Hdr.Name = "."
//	o.Hdr.Rrtype = dns.TypeOPT
//	e := new(dns.EDNS0_SUBNET)
//	e.Code = dns.EDNS0SUBNET // by default this is filled in through unpacking OPT packets (unpackDataOpt)
//	e.Family = 1	// 1 for IPv4 source address, 2 for IPv6
//	e.SourceNetmask = 32	// 32 for IPV4, 128 for IPv6
//	e.SourceScope = 0
//	e.Address = net.ParseIP("127.0.0.1").To4()	// for IPv4
//	// e.Address = net.ParseIP("2001:7b8:32a::2")	// for IPV6
//	o.Option = append(o.Option, e)
//
// This code will parse all the available bits when unpacking (up to optlen).
// When packing it will apply SourceNetmask. If you need more advanced logic,
// patches welcome and good luck.
type EDNS0_SUBNET struct {
	Code          uint16 // always EDNS0SUBNET
	Family        uint16 // 1 for IP, 2 for IP6
	SourceNetmask uint8
	SourceScope   uint8
	Address       netip.Addr
}

// Option implements the EDNS0 interface.
func (e *EDNS0_SUBNET) Option() uint16 { return EDNS0SUBNET }

func (e *EDNS0_SUBNET) pack() ([]byte, error) {
	switch e.Family {
	case 0:
		// "dig" sets AddressFamily to 0 if SourceNetmask is also 0
		// We might don't need to complain either
		if e.SourceNetmask != 0 {
			return nil, errors.New("bad address family")
		}
	case 1:
		if e.SourceNetmask > net.IPv4len*8 {
			return nil, errors.New("bad netmask")
		}
		if !e.Address.Is4() {
			return nil, errors.New("bad address")
		}
	case 2:
		if e.SourceNetmask > net.IPv6len*8 {
			return nil, errors.New("bad netmask")
		}
		if !e.Address.Is6() {
			return nil, errors.New("bad address")
		}
	default:
		return nil, errors.New("bad address family")
	}

	ip := netip.PrefixFrom(e.Address, int(e.SourceNetmask)).Masked().Addr()
	needLength := (e.SourceNetmask + 8 - 1) / 8 // division rounding up

	b := make([]byte, 4+needLength)
	binary.BigEndian.PutUint16(b[0:], e.Family)
	b[2] = e.SourceNetmask
	b[3] = e.SourceScope
	copy(b[4:], ip.AsSlice())

	return b, nil
}

func (e *EDNS0_SUBNET) unpack(b []byte) error {
	if len(b) < 4 {
		return ErrBuf
	}
	e.Family = binary.BigEndian.Uint16(b)
	e.SourceNetmask = b[2]
	e.SourceScope = b[3]

	var ipLen uint8
	switch e.Family {
	case 0:
		// "dig" sets AddressFamily to 0 if SourceNetmask is also 0
		// It's okay to accept such a packet
		if e.SourceNetmask != 0 {
			return errors.New("bad address family")
		}
		e.Address = netip.AddrFrom4([4]byte{0, 0, 0, 0})
		return nil
	case 1:
		ipLen = net.IPv4len
	case 2:
		ipLen = net.IPv6len
	default:
		return errors.New("bad address family")
	}

	if e.SourceNetmask > ipLen*8 || e.SourceScope > ipLen*8 {
		return errors.New("bad netmask")
	}
	ip := make([]byte, ipLen)
	copy(ip, b[4:])
	e.Address, _ = netip.AddrFromSlice(ip)
	return nil
}

func (e *EDNS0_SUBNET) String() string {
	var s strings.Builder
	if !e.Address.IsValid() {
		s.WriteString("<nil>")
	} else if e.Address.Is4() {
		s.WriteString(e.Address.String())
	} else {
		s.WriteByte('[')
		s.WriteString(e.Address.String())
		s.WriteByte(']')
	}
	s.WriteByte('/')
	s.WriteString(strconv.Itoa(int(e.SourceNetmask)))
	s.WriteByte('/')
	s.WriteString(strconv.Itoa(int(e.SourceScope)))
	return s.String()
}

func (e *EDNS0_SUBNET) copy() EDNS0 {
	return &EDNS0_SUBNET{
		e.Code,
		e.Family,
		e.SourceNetmask,
		e.SourceScope,
		e.Address,
	}
}

// The EDNS0_COOKIE option is used to add a DNS Cookie to a message.
//
//	o := new(dns.OPT)
//	o.Hdr.Name = "."
//	o.Hdr.Rrtype = dns.TypeOPT
//	e := new(dns.EDNS0_COOKIE)
//	e.Code = dns.EDNS0COOKIE
//	e.Cookie = "24a5ac.."
//	o.Option = append(o.Option, e)
//
// The Cookie field consists out of a client cookie (RFC 7873 Section 4), that is
// always 8 bytes. It may then optionally be followed by the server cookie. The server
// cookie is of variable length, 8 to a maximum of 32 bytes. In other words:
//
//	cCookie := o.Cookie[:16]
//	sCookie := o.Cookie[16:]
//
// There is no guarantee that the Cookie string has a specific length.
type EDNS0_COOKIE struct {
	Code   uint16    // always EDNS0COOKIE
	Cookie ByteField `dns:"hex"`
}

func (e *EDNS0_COOKIE) pack() ([]byte, error) {
	return e.Cookie.Raw(), nil
}

// Option implements the EDNS0 interface.
func (e *EDNS0_COOKIE) Option() uint16        { return EDNS0COOKIE }
func (e *EDNS0_COOKIE) unpack(b []byte) error { e.Cookie = BFFromBytes(b); return nil }
func (e *EDNS0_COOKIE) String() string        { return e.Cookie.Hex() }
func (e *EDNS0_COOKIE) copy() EDNS0           { return &EDNS0_COOKIE{e.Code, e.Cookie} }

// The EDNS0_UL (Update Lease) (draft RFC) option is used to tell the server to set
// an expiration on an update RR. This is helpful for clients that cannot clean
// up after themselves. This is a draft RFC and more information can be found at
// https://tools.ietf.org/html/draft-sekar-dns-ul-02
//
//	o := new(dns.OPT)
//	o.Hdr.Name = "."
//	o.Hdr.Rrtype = dns.TypeOPT
//	e := new(dns.EDNS0_UL)
//	e.Code = dns.EDNS0UL
//	e.Lease = 120 // in seconds
//	o.Option = append(o.Option, e)
type EDNS0_UL struct {
	Code     uint16 // always EDNS0UL
	Lease    uint32
	KeyLease uint32
}

// Option implements the EDNS0 interface.
func (e *EDNS0_UL) Option() uint16 { return EDNS0UL }
func (e *EDNS0_UL) String() string { return fmt.Sprintf("%d %d", e.Lease, e.KeyLease) }
func (e *EDNS0_UL) copy() EDNS0    { return &EDNS0_UL{e.Code, e.Lease, e.KeyLease} }

// Copied: http://golang.org/src/pkg/net/dnsmsg.go
func (e *EDNS0_UL) pack() ([]byte, error) {
	var b []byte
	if e.KeyLease == 0 {
		b = make([]byte, 4)
	} else {
		b = make([]byte, 8)
		binary.BigEndian.PutUint32(b[4:], e.KeyLease)
	}
	binary.BigEndian.PutUint32(b, e.Lease)
	return b, nil
}

func (e *EDNS0_UL) unpack(b []byte) error {
	switch len(b) {
	case 4:
		e.KeyLease = 0
	case 8:
		e.KeyLease = binary.BigEndian.Uint32(b[4:])
	default:
		return ErrBuf
	}
	e.Lease = binary.BigEndian.Uint32(b)
	return nil
}

// EDNS0_LLQ stands for Long Lived Queries: http://tools.ietf.org/html/draft-sekar-dns-llq-01
// Implemented for completeness, as the EDNS0 type code is assigned.
type EDNS0_LLQ struct {
	Code      uint16 // always EDNS0LLQ
	Version   uint16
	Opcode    uint16
	Error     uint16
	Id        uint64
	LeaseLife uint32
}

// Option implements the EDNS0 interface.
func (e *EDNS0_LLQ) Option() uint16 { return EDNS0LLQ }

func (e *EDNS0_LLQ) pack() ([]byte, error) {
	b := make([]byte, 18)
	binary.BigEndian.PutUint16(b[0:], e.Version)
	binary.BigEndian.PutUint16(b[2:], e.Opcode)
	binary.BigEndian.PutUint16(b[4:], e.Error)
	binary.BigEndian.PutUint64(b[6:], e.Id)
	binary.BigEndian.PutUint32(b[14:], e.LeaseLife)
	return b, nil
}

func (e *EDNS0_LLQ) unpack(b []byte) error {
	if len(b) < 18 {
		return ErrBuf
	}
	e.Version = binary.BigEndian.Uint16(b[0:])
	e.Opcode = binary.BigEndian.Uint16(b[2:])
	e.Error = binary.BigEndian.Uint16(b[4:])
	e.Id = binary.BigEndian.Uint64(b[6:])
	e.LeaseLife = binary.BigEndian.Uint32(b[14:])
	return nil
}

func (e *EDNS0_LLQ) String() string {
	var s strings.Builder
	s.WriteString(strconv.FormatUint(uint64(e.Version), 10))
	s.WriteByte(' ')
	s.WriteString(strconv.FormatUint(uint64(e.Opcode), 10))
	s.WriteByte(' ')
	s.WriteString(strconv.FormatUint(uint64(e.Error), 10))
	s.WriteByte(' ')
	s.WriteString(strconv.FormatUint(e.Id, 10))
	s.WriteByte(' ')
	s.WriteString(strconv.FormatUint(uint64(e.LeaseLife), 10))
	return s.String()
}

func (e *EDNS0_LLQ) copy() EDNS0 {
	return &EDNS0_LLQ{e.Code, e.Version, e.Opcode, e.Error, e.Id, e.LeaseLife}
}

// EDNS0_DAU implements the EDNS0 "DNSSEC Algorithm Understood" option. See RFC 6975.
type EDNS0_DAU struct {
	Code    uint16 // always EDNS0DAU
	AlgCode []uint8
}

// Option implements the EDNS0 interface.
func (e *EDNS0_DAU) Option() uint16        { return EDNS0DAU }
func (e *EDNS0_DAU) pack() ([]byte, error) { return slices.Clone(e.AlgCode), nil }
func (e *EDNS0_DAU) unpack(b []byte) error { e.AlgCode = slices.Clone(b); return nil }

func (e *EDNS0_DAU) String() string {
	var s strings.Builder
	for _, alg := range e.AlgCode {
		s.WriteByte(' ')
		if a, ok := AlgorithmToString[alg]; ok {
			s.WriteString(a)
		} else {
			s.WriteString(strconv.Itoa(int(alg)))
		}
	}
	return s.String()
}

func (e *EDNS0_DAU) copy() EDNS0 { return &EDNS0_DAU{e.Code, e.AlgCode} }

// EDNS0_DHU implements the EDNS0 "DS Hash Understood" option. See RFC 6975.
type EDNS0_DHU struct {
	Code    uint16 // always EDNS0DHU
	AlgCode []uint8
}

// Option implements the EDNS0 interface.
func (e *EDNS0_DHU) Option() uint16        { return EDNS0DHU }
func (e *EDNS0_DHU) pack() ([]byte, error) { return slices.Clone(e.AlgCode), nil }
func (e *EDNS0_DHU) unpack(b []byte) error { e.AlgCode = slices.Clone(b); return nil }

func (e *EDNS0_DHU) String() string {
	var s strings.Builder
	for _, alg := range e.AlgCode {
		s.WriteByte(' ')
		if a, ok := HashToString[alg]; ok {
			s.WriteString(a)
		} else {
			s.WriteString(strconv.Itoa(int(alg)))
		}
	}
	return s.String()
}
func (e *EDNS0_DHU) copy() EDNS0 { return &EDNS0_DHU{e.Code, e.AlgCode} }

// EDNS0_N3U implements the EDNS0 "NSEC3 Hash Understood" option. See RFC 6975.
type EDNS0_N3U struct {
	Code    uint16 // always EDNS0N3U
	AlgCode []uint8
}

// Option implements the EDNS0 interface.
func (e *EDNS0_N3U) Option() uint16        { return EDNS0N3U }
func (e *EDNS0_N3U) pack() ([]byte, error) { return slices.Clone(e.AlgCode), nil }
func (e *EDNS0_N3U) unpack(b []byte) error { e.AlgCode = slices.Clone(b); return nil }

func (e *EDNS0_N3U) String() string {
	// Re-use the hash map
	var s strings.Builder
	for _, alg := range e.AlgCode {
		s.WriteByte(' ')
		if a, ok := HashToString[alg]; ok {
			s.WriteString(a)
		} else {
			s.WriteString(strconv.Itoa(int(alg)))
		}
	}
	return s.String()
}
func (e *EDNS0_N3U) copy() EDNS0 { return &EDNS0_N3U{e.Code, e.AlgCode} }

// EDNS0_EXPIRE implements the EDNS0 option as described in RFC 7314.
type EDNS0_EXPIRE struct {
	Code   uint16 // always EDNS0EXPIRE
	Expire uint32
	Empty  bool // Empty is used to signal an empty Expire option in a backwards compatible way, it's not used on the wire.
}

// Option implements the EDNS0 interface.
func (e *EDNS0_EXPIRE) Option() uint16 { return EDNS0EXPIRE }
func (e *EDNS0_EXPIRE) copy() EDNS0    { return &EDNS0_EXPIRE{e.Code, e.Expire, e.Empty} }

func (e *EDNS0_EXPIRE) pack() ([]byte, error) {
	if e.Empty {
		return []byte{}, nil
	}
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, e.Expire)
	return b, nil
}

func (e *EDNS0_EXPIRE) unpack(b []byte) error {
	if len(b) == 0 {
		// zero-length EXPIRE query, see RFC 7314 Section 2
		e.Empty = true
		return nil
	}
	if len(b) < 4 {
		return ErrBuf
	}
	e.Expire = binary.BigEndian.Uint32(b)
	e.Empty = false
	return nil
}

func (e *EDNS0_EXPIRE) String() (s string) {
	if e.Empty {
		return ""
	}
	return strconv.FormatUint(uint64(e.Expire), 10)
}

// The EDNS0_LOCAL option is used for local/experimental purposes. The option
// code is recommended to be within the range [EDNS0LOCALSTART, EDNS0LOCALEND]
// (RFC6891), although any unassigned code can actually be used.  The content of
// the option is made available in Data, unaltered.
// Basic use pattern for creating a local option:
//
//	o := new(dns.OPT)
//	o.Hdr.Name = "."
//	o.Hdr.Rrtype = dns.TypeOPT
//	e := new(dns.EDNS0_LOCAL)
//	e.Code = dns.EDNS0LOCALSTART
//	e.Data = []byte{72, 82, 74}
//	o.Option = append(o.Option, e)
type EDNS0_LOCAL struct {
	Code uint16
	Data ByteField `dns:"hex"`
}

// Option implements the EDNS0 interface.
func (e *EDNS0_LOCAL) Option() uint16 { return e.Code }

func (e *EDNS0_LOCAL) String() string {
	return strconv.FormatInt(int64(e.Code), 10) + ":0x" + e.Data.Hex()
}

func (e *EDNS0_LOCAL) copy() EDNS0 {
	return &EDNS0_LOCAL{e.Code, e.Data}
}

func (e *EDNS0_LOCAL) pack() ([]byte, error) {
	return e.Data.Raw(), nil
}

func (e *EDNS0_LOCAL) unpack(b []byte) error {
	e.Data = BFFromBytes(b)
	return nil
}

// EDNS0_TCP_KEEPALIVE is an EDNS0 option that instructs the server to keep
// the TCP connection alive. See RFC 7828.
type EDNS0_TCP_KEEPALIVE struct {
	Code uint16 // always EDNSTCPKEEPALIVE

	// Timeout is an idle timeout value for the TCP connection, specified in
	// units of 100 milliseconds, encoded in network byte order. If set to 0,
	// pack will return a nil slice.
	Timeout uint16

	// Length is the option's length.
	// Deprecated: this field is deprecated and is always equal to 0.
	Length uint16
}

// Option implements the EDNS0 interface.
func (e *EDNS0_TCP_KEEPALIVE) Option() uint16 { return EDNS0TCPKEEPALIVE }

func (e *EDNS0_TCP_KEEPALIVE) pack() ([]byte, error) {
	if e.Timeout > 0 {
		b := make([]byte, 2)
		binary.BigEndian.PutUint16(b, e.Timeout)
		return b, nil
	}
	return nil, nil
}

func (e *EDNS0_TCP_KEEPALIVE) unpack(b []byte) error {
	switch len(b) {
	case 0:
	case 2:
		e.Timeout = binary.BigEndian.Uint16(b)
	default:
		return fmt.Errorf("length mismatch, want 0/2 but got %d", len(b))
	}
	return nil
}

func (e *EDNS0_TCP_KEEPALIVE) String() string {
	var s strings.Builder
	s.WriteString("use tcp keep-alive, timeout ")
	if e.Timeout == 0 {
		s.WriteString("omitted")
	} else {
		s.WriteString(fmt.Sprintf("%dms", e.Timeout*100))
	}
	return s.String()
}

func (e *EDNS0_TCP_KEEPALIVE) copy() EDNS0 { return &EDNS0_TCP_KEEPALIVE{e.Code, e.Timeout, e.Length} }

// EDNS0_PADDING option is used to add padding to a request/response. The default
// value of padding SHOULD be 0x0 but other values MAY be used, for instance if
// compression is applied before encryption which may break signatures.
type EDNS0_PADDING struct {
	Padding ByteField
}

// Option implements the EDNS0 interface.
func (e *EDNS0_PADDING) Option() uint16        { return EDNS0PADDING }
func (e *EDNS0_PADDING) pack() ([]byte, error) { return e.Padding.Raw(), nil }
func (e *EDNS0_PADDING) unpack(b []byte) error { e.Padding = BFFromBytes(b); return nil }
func (e *EDNS0_PADDING) String() string        { return e.Padding.Hex() }
func (e *EDNS0_PADDING) copy() EDNS0           { return &EDNS0_PADDING{e.Padding} }

// Extended DNS Error Codes (RFC 8914).
const (
	ExtendedErrorCodeOther uint16 = iota
	ExtendedErrorCodeUnsupportedDNSKEYAlgorithm
	ExtendedErrorCodeUnsupportedDSDigestType
	ExtendedErrorCodeStaleAnswer
	ExtendedErrorCodeForgedAnswer
	ExtendedErrorCodeDNSSECIndeterminate
	ExtendedErrorCodeDNSBogus
	ExtendedErrorCodeSignatureExpired
	ExtendedErrorCodeSignatureNotYetValid
	ExtendedErrorCodeDNSKEYMissing
	ExtendedErrorCodeRRSIGsMissing
	ExtendedErrorCodeNoZoneKeyBitSet
	ExtendedErrorCodeNSECMissing
	ExtendedErrorCodeCachedError
	ExtendedErrorCodeNotReady
	ExtendedErrorCodeBlocked
	ExtendedErrorCodeCensored
	ExtendedErrorCodeFiltered
	ExtendedErrorCodeProhibited
	ExtendedErrorCodeStaleNXDOMAINAnswer
	ExtendedErrorCodeNotAuthoritative
	ExtendedErrorCodeNotSupported
	ExtendedErrorCodeNoReachableAuthority
	ExtendedErrorCodeNetworkError
	ExtendedErrorCodeInvalidData
	ExtendedErrorCodeSignatureExpiredBeforeValid
	ExtendedErrorCodeTooEarly
	ExtendedErrorCodeUnsupportedNSEC3IterValue
	ExtendedErrorCodeUnableToConformToPolicy
	ExtendedErrorCodeSynthesized
	ExtendedErrorCodeInvalidQueryType
)

// ExtendedErrorCodeToString maps extended error info codes to a human readable
// description.
var ExtendedErrorCodeToString = map[uint16]string{
	ExtendedErrorCodeOther:                       "Other",
	ExtendedErrorCodeUnsupportedDNSKEYAlgorithm:  "Unsupported DNSKEY Algorithm",
	ExtendedErrorCodeUnsupportedDSDigestType:     "Unsupported DS Digest Type",
	ExtendedErrorCodeStaleAnswer:                 "Stale Answer",
	ExtendedErrorCodeForgedAnswer:                "Forged Answer",
	ExtendedErrorCodeDNSSECIndeterminate:         "DNSSEC Indeterminate",
	ExtendedErrorCodeDNSBogus:                    "DNSSEC Bogus",
	ExtendedErrorCodeSignatureExpired:            "Signature Expired",
	ExtendedErrorCodeSignatureNotYetValid:        "Signature Not Yet Valid",
	ExtendedErrorCodeDNSKEYMissing:               "DNSKEY Missing",
	ExtendedErrorCodeRRSIGsMissing:               "RRSIGs Missing",
	ExtendedErrorCodeNoZoneKeyBitSet:             "No Zone Key Bit Set",
	ExtendedErrorCodeNSECMissing:                 "NSEC Missing",
	ExtendedErrorCodeCachedError:                 "Cached Error",
	ExtendedErrorCodeNotReady:                    "Not Ready",
	ExtendedErrorCodeBlocked:                     "Blocked",
	ExtendedErrorCodeCensored:                    "Censored",
	ExtendedErrorCodeFiltered:                    "Filtered",
	ExtendedErrorCodeProhibited:                  "Prohibited",
	ExtendedErrorCodeStaleNXDOMAINAnswer:         "Stale NXDOMAIN Answer",
	ExtendedErrorCodeNotAuthoritative:            "Not Authoritative",
	ExtendedErrorCodeNotSupported:                "Not Supported",
	ExtendedErrorCodeNoReachableAuthority:        "No Reachable Authority",
	ExtendedErrorCodeNetworkError:                "Network Error",
	ExtendedErrorCodeInvalidData:                 "Invalid Data",
	ExtendedErrorCodeSignatureExpiredBeforeValid: "Signature Expired Before Valid",
	ExtendedErrorCodeTooEarly:                    "Too Early",
	ExtendedErrorCodeUnsupportedNSEC3IterValue:   "Unsupported NSEC3 Iterations Value",
	ExtendedErrorCodeUnableToConformToPolicy:     "Unable To Conform To Policy",
	ExtendedErrorCodeSynthesized:                 "Synthesized",
	ExtendedErrorCodeInvalidQueryType:            "Invalid Query Type",
}

// StringToExtendedErrorCode is a map from human readable descriptions to
// extended error info codes.
var StringToExtendedErrorCode = reverseMap(ExtendedErrorCodeToString)

// EDNS0_EDE option is used to return additional information about the cause of
// DNS errors.
type EDNS0_EDE struct {
	InfoCode  uint16
	ExtraText string
}

// Option implements the EDNS0 interface.
func (e *EDNS0_EDE) Option() uint16 { return EDNS0EDE }
func (e *EDNS0_EDE) copy() EDNS0    { return &EDNS0_EDE{e.InfoCode, e.ExtraText} }

func (e *EDNS0_EDE) String() string {
	info := strconv.FormatUint(uint64(e.InfoCode), 10)
	if s, ok := ExtendedErrorCodeToString[e.InfoCode]; ok {
		info += fmt.Sprintf(" (%s)", s)
	}
	return fmt.Sprintf("%s: (%s)", info, e.ExtraText)
}

func (e *EDNS0_EDE) pack() ([]byte, error) {
	b := make([]byte, 2+len(e.ExtraText))
	binary.BigEndian.PutUint16(b[0:], e.InfoCode)
	copy(b[2:], e.ExtraText)
	return b, nil
}

func (e *EDNS0_EDE) unpack(b []byte) error {
	if len(b) < 2 {
		return ErrBuf
	}
	e.InfoCode = binary.BigEndian.Uint16(b[0:])
	e.ExtraText = string(b[2:])
	return nil
}

// The EDNS0_ESU option for ENUM Source-URI Extension.
type EDNS0_ESU struct {
	Code uint16 // always EDNS0ESU
	Uri  string
}

func (e *EDNS0_ESU) Option() uint16        { return EDNS0ESU }
func (e *EDNS0_ESU) String() string        { return e.Uri }
func (e *EDNS0_ESU) copy() EDNS0           { return &EDNS0_ESU{e.Code, e.Uri} }
func (e *EDNS0_ESU) pack() ([]byte, error) { return []byte(e.Uri), nil }
func (e *EDNS0_ESU) unpack(b []byte) error {
	e.Uri = string(b)
	return nil
}
