package dns

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"
)

type (
	// Type is a DNS type.
	Type uint16
	// Class is a DNS class.
	Class uint16
)

// Packet formats

// Wire constants and supported types.
const (
	// valid RR_Header.Rrtype and Question.qtype

	TypeRESERVED0 Type = 0
	TypeA         Type = 1
	TypeNS        Type = 2
	TypeMD        Type = 3
	TypeMF        Type = 4
	TypeCNAME     Type = 5
	TypeSOA       Type = 6
	TypeMB        Type = 7
	TypeMG        Type = 8
	TypeMR        Type = 9
	TypeNULL      Type = 10
	// TypeWKS  Type = 11
	TypePTR   Type = 12
	TypeHINFO Type = 13
	TypeMINFO Type = 14
	TypeMX    Type = 15
	TypeTXT   Type = 16
	TypeRP    Type = 17
	TypeAFSDB Type = 18
	TypeX25   Type = 19
	TypeISDN  Type = 20
	TypeRT    Type = 21
	// TypeNSAP    Type = 22
	TypeNSAPPTR Type = 23
	TypeSIG     Type = 24
	TypeKEY     Type = 25
	TypePX      Type = 26
	TypeGPOS    Type = 27
	TypeAAAA    Type = 28
	TypeLOC     Type = 29
	TypeNXT     Type = 30
	TypeEID     Type = 31
	TypeNIMLOC  Type = 32
	TypeSRV     Type = 33
	TypeATMA    Type = 34
	TypeNAPTR   Type = 35
	TypeKX      Type = 36
	TypeCERT    Type = 37
	// TypeA6 Type = 38
	TypeDNAME Type = 39
	// TypeSINK Type = 40
	TypeOPT        Type = 41 // EDNS
	TypeAPL        Type = 42
	TypeDS         Type = 43
	TypeSSHFP      Type = 44
	TypeIPSECKEY   Type = 45
	TypeRRSIG      Type = 46
	TypeNSEC       Type = 47
	TypeDNSKEY     Type = 48
	TypeDHCID      Type = 49
	TypeNSEC3      Type = 50
	TypeNSEC3PARAM Type = 51
	TypeTLSA       Type = 52
	TypeSMIMEA     Type = 53
	// unassigned 54
	TypeHIP        Type = 55
	TypeNINFO      Type = 56
	TypeRKEY       Type = 57
	TypeTALINK     Type = 58
	TypeCDS        Type = 59
	TypeCDNSKEY    Type = 60
	TypeOPENPGPKEY Type = 61
	TypeCSYNC      Type = 62
	TypeZONEMD     Type = 63
	TypeSVCB       Type = 64
	TypeHTTPS      Type = 65
	// TypeDSYNC Type = 66
	// TypeHHIT  Type = 67
	// TypeBRID  Type = 68
	// unassigned 69-98
	TypeSPF    Type = 99
	TypeUINFO  Type = 100
	TypeUID    Type = 101
	TypeGID    Type = 102
	TypeUNSPEC Type = 103
	TypeNID    Type = 104
	TypeL32    Type = 105
	TypeL64    Type = 106
	TypeLP     Type = 107
	TypeEUI48  Type = 108
	TypeEUI64  Type = 109
	// unassigned 110-127
	TypeNXNAME Type = 128
	// unassigned 129-248
	// 249-255 defined below
	TypeURI Type = 256
	TypeCAA Type = 257
	TypeAVC Type = 258
	// TypeDOA Type = 259
	TypeAMTRELAY Type = 260
	TypeRESINFO  Type = 261
	// TypeWALLET Type = 262
	// TypeCLA Type = 263
	// TypeIPN Type = 264

	TypeTKEY Type = 249
	TypeTSIG Type = 250

	// valid Question.Qtype only
	TypeIXFR  Type = 251
	TypeAXFR  Type = 252
	TypeMAILB Type = 253
	TypeMAILA Type = 254
	TypeANY   Type = 255

	TypeTA            Type = 32768
	TypeDLV           Type = 32769
	TypeRESERVED65535 Type = 65535

	// valid Question.Qclass
	ClassINET   Class = 1
	ClassCSNET  Class = 2
	ClassCHAOS  Class = 3
	ClassHESIOD Class = 4
	ClassNONE   Class = 254
	ClassANY    Class = 255

	// Message Response Codes, see https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml
	RcodeSuccess                    = 0  // NoError   - No Error                          [DNS]
	RcodeFormatError                = 1  // FormErr   - Format Error                      [DNS]
	RcodeServerFailure              = 2  // ServFail  - Server Failure                    [DNS]
	RcodeNameError                  = 3  // NXDomain  - Non-Existent Domain               [DNS]
	RcodeNotImplemented             = 4  // NotImp    - Not Implemented                   [DNS]
	RcodeRefused                    = 5  // Refused   - Query Refused                     [DNS]
	RcodeYXDomain                   = 6  // YXDomain  - Name Exists when it should not    [DNS Update]
	RcodeYXRrset                    = 7  // YXRRSet   - RR Set Exists when it should not  [DNS Update]
	RcodeNXRrset                    = 8  // NXRRSet   - RR Set that should exist does not [DNS Update]
	RcodeNotAuth                    = 9  // NotAuth   - Server Not Authoritative for zone [DNS Update]
	RcodeNotZone                    = 10 // NotZone   - Name not contained in zone        [DNS Update/TSIG]
	RcodeStatefulTypeNotImplemented = 11 // DSOTypeNI - DSO-TYPE not implemented          [DNS Stateful Operations] https://www.rfc-editor.org/rfc/rfc8490.html#section-10.2
	RcodeBadSig                     = 16 // BADSIG    - TSIG Signature Failure            [TSIG]  https://www.rfc-editor.org/rfc/rfc6895.html#section-2.3
	RcodeBadVers                    = 16 // BADVERS   - Bad OPT Version                   [EDNS0] https://www.rfc-editor.org/rfc/rfc6895.html#section-2.3
	RcodeBadKey                     = 17 // BADKEY    - Key not recognized                [TSIG]
	RcodeBadTime                    = 18 // BADTIME   - Signature out of time window      [TSIG]
	RcodeBadMode                    = 19 // BADMODE   - Bad TKEY Mode                     [TKEY]
	RcodeBadName                    = 20 // BADNAME   - Duplicate key name                [TKEY]
	RcodeBadAlg                     = 21 // BADALG    - Algorithm not supported           [TKEY]
	RcodeBadTrunc                   = 22 // BADTRUNC  - Bad Truncation                    [TSIG]
	RcodeBadCookie                  = 23 // BADCOOKIE - Bad/missing Server Cookie         [DNS Cookies]

	// Message Opcodes. There is no 3.
	OpcodeQuery    = 0
	OpcodeIQuery   = 1
	OpcodeStatus   = 2
	OpcodeNotify   = 4
	OpcodeUpdate   = 5
	OpcodeStateful = 6
)

// Used in ZONEMD https://tools.ietf.org/html/rfc8976
const (
	ZoneMDSchemeSimple = 1

	ZoneMDHashAlgSHA384 = 1
	ZoneMDHashAlgSHA512 = 2
)

// Used in IPSEC https://datatracker.ietf.org/doc/html/rfc4025#section-2.3
const (
	IPSECGatewayNone uint8 = iota
	IPSECGatewayIPv4
	IPSECGatewayIPv6
	IPSECGatewayHost
)

// Used in AMTRELAY https://datatracker.ietf.org/doc/html/rfc8777#section-4.2.3
const (
	AMTRELAYNone = IPSECGatewayNone
	AMTRELAYIPv4 = IPSECGatewayIPv4
	AMTRELAYIPv6 = IPSECGatewayIPv6
	AMTRELAYHost = IPSECGatewayHost
)

// Stateful types as defined in RFC 8490.
const (
	StatefulTypeKeepAlive uint16 = iota + 1
	StatefulTypeRetryDelay
	StatefulTypeEncryptionPadding
)

var StatefulTypeToString = map[uint16]string{
	StatefulTypeKeepAlive:         "KeepAlive",
	StatefulTypeRetryDelay:        "RetryDelay",
	StatefulTypeEncryptionPadding: "EncryptionPadding",
}

// Header is the wire format for the DNS packet header.
type Header struct {
	Id                                 uint16
	Bits                               uint16
	Qdcount, Ancount, Nscount, Arcount uint16
}

const (
	headerSize = 12

	// Header.Bits
	_QR = 1 << 15 // query/response (response=1)
	_AA = 1 << 10 // authoritative
	_TC = 1 << 9  // truncated
	_RD = 1 << 8  // recursion desired
	_RA = 1 << 7  // recursion available
	_Z  = 1 << 6  // Z
	_AD = 1 << 5  // authenticated data
	_CD = 1 << 4  // checking disabled
)

// Various constants used in the LOC RR. See RFC 1876.
const (
	LOC_EQUATOR       = 1 << 31 // RFC 1876, Section 2.
	LOC_PRIMEMERIDIAN = 1 << 31 // RFC 1876, Section 2.
	LOC_HOURS         = 60 * 1000
	LOC_DEGREES       = 60 * LOC_HOURS
	LOC_ALTITUDEBASE  = 100000
)

// Different Certificate Types, see RFC 4398, Section 2.1
const (
	CertPKIX = 1 + iota
	CertSPKI
	CertPGP
	CertIPIX
	CertISPKI
	CertIPGP
	CertACPKIX
	CertIACPKIX
	CertURI = 253
	CertOID = 254
)

// CertTypeToString converts the Cert Type to its string representation.
// See RFC 4398 and RFC 6944.
var CertTypeToString = map[uint16]string{
	CertPKIX:    "PKIX",
	CertSPKI:    "SPKI",
	CertPGP:     "PGP",
	CertIPIX:    "IPIX",
	CertISPKI:   "ISPKI",
	CertIPGP:    "IPGP",
	CertACPKIX:  "ACPKIX",
	CertIACPKIX: "IACPKIX",
	CertURI:     "URI",
	CertOID:     "OID",
}

//go:generate go run types_generate.go

// Question holds a DNS question. Usually there is just one. While the
// original DNS RFCs allow multiple questions in the question section of a
// message, in practice it never works. Because most DNS servers see multiple
// questions as an error, it is recommended to only have one question per
// message.
type Question struct {
	Name   Name `dns:"cdomain-name"` // "cdomain-name" specifies encoding (and may be compressed)
	Qtype  Type
	Qclass Class
}

func (q *Question) len(off int, compression map[Name]struct{}) int {
	l := domainNameLen(q.Name, off, compression, true)
	l += 2 + 2
	return l
}

func (q *Question) String() (s string) {
	// prefix with ; (as in dig)
	s = ";" + q.Name.String() + "\t"
	s += Class(q.Qclass).String() + "\t"
	s += " " + Type(q.Qtype).String()
	return s
}

// ANY is a wild card record. See RFC 1035, Section 3.2.3. ANY is named "*" there.
// The ANY records can be (ab)used to create resource records without any rdata, that
// can be used in dynamic update requests. Basic use pattern:
//
//	a := &ANY{RR_Header{
//		Name:   "example.org.",
//		Rrtype: TypeA,
//		Class:  ClassINET,
//	}}
//
// Results in an A record without rdata.
type ANY struct {
	Hdr RR_Header
	// Does not have any rdata.
}

func (*ANY) parse(c *zlexer, origin Name) *ParseError {
	return &ParseError{err: "ANY records do not have a presentation format"}
}

// NULL RR. See RFC 1035.
type NULL struct {
	Hdr  RR_Header
	Data ByteField `dns:"hex"`
}

func (*NULL) parse(c *zlexer, origin Name) *ParseError {
	return &ParseError{err: "NULL records do not have a presentation format"}
}

// NXNAME is a meta record. See https://www.iana.org/go/draft-ietf-dnsop-compact-denial-of-existence-04
// Reference: https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml
type NXNAME struct {
	Hdr RR_Header
	// Does not have any rdata
}

func (*NXNAME) parse(c *zlexer, origin Name) *ParseError {
	return &ParseError{err: "NXNAME records do not have a presentation format"}
}

// CNAME RR. See RFC 1034.
type CNAME struct {
	Hdr    RR_Header
	Target Name `dns:"cdomain-name"`
}

// HINFO RR. See RFC 1034.
type HINFO struct {
	Hdr RR_Header
	Cpu TxtString
	Os  TxtString
}

// MB RR. See RFC 1035.
type MB struct {
	Hdr RR_Header
	Mb  Name `dns:"cdomain-name"`
}

// MG RR. See RFC 1035.
type MG struct {
	Hdr RR_Header
	Mg  Name `dns:"cdomain-name"`
}

// MINFO RR. See RFC 1035.
type MINFO struct {
	Hdr   RR_Header
	Rmail Name `dns:"cdomain-name"`
	Email Name `dns:"cdomain-name"`
}

// MR RR. See RFC 1035.
type MR struct {
	Hdr RR_Header
	Mr  Name `dns:"cdomain-name"`
}

// MF RR. See RFC 1035.
type MF struct {
	Hdr RR_Header
	Mf  Name `dns:"cdomain-name"`
}

// MD RR. See RFC 1035.
type MD struct {
	Hdr RR_Header
	Md  Name `dns:"cdomain-name"`
}

// MX RR. See RFC 1035.
type MX struct {
	Hdr        RR_Header
	Preference uint16
	Mx         Name `dns:"cdomain-name"`
}

// AFSDB RR. See RFC 1183.
type AFSDB struct {
	Hdr      RR_Header
	Subtype  uint16
	Hostname Name
}

// X25 RR. See RFC 1183, Section 3.1.
type X25 struct {
	Hdr         RR_Header
	PSDNAddress TxtString `dns:"baretxt"`
}

// ISDN RR. See RFC 1183, Section 3.2.
type ISDN struct {
	Hdr        RR_Header
	Address    TxtString
	SubAddress TxtString
}

// RT RR. See RFC 1183, Section 3.3.
type RT struct {
	Hdr        RR_Header
	Preference uint16
	Host       Name // RFC 3597 prohibits compressing records not defined in RFC 1035.
}

// NS RR. See RFC 1035.
type NS struct {
	Hdr RR_Header
	Ns  Name `dns:"cdomain-name"`
}

// PTR RR. See RFC 1035.
type PTR struct {
	Hdr RR_Header
	Ptr Name `dns:"cdomain-name"`
}

// RP RR. See RFC 1138, Section 2.2.
type RP struct {
	Hdr  RR_Header
	Mbox Name
	Txt  Name
}

// SOA RR. See RFC 1035.
type SOA struct {
	Hdr     RR_Header
	Ns      Name `dns:"cdomain-name"`
	Mbox    Name `dns:"cdomain-name"`
	Serial  uint32
	Refresh uint32
	Retry   uint32
	Expire  uint32
	Minttl  uint32
}

// TXT RR. See RFC 1035.
type TXT struct {
	Hdr RR_Header
	Txt TxtStrings
}

func sprintTxtOctet(s string) string {
	var dst strings.Builder
	dst.Grow(2 + len(s))
	dst.WriteByte('"')
	for i := 0; i < len(s); {
		if i+1 < len(s) && s[i] == '\\' && s[i+1] == '.' {
			dst.WriteString(s[i : i+2])
			i += 2
			continue
		}

		b, n := nextByte(s, i)
		if n == 0 {
			i++ // dangling back slash
		} else {
			writeTXTStringByte(&dst, b)
		}
		i += n
	}
	dst.WriteByte('"')
	return dst.String()
}

func sprintTxt(txt []string) string {
	var out strings.Builder
	for i, s := range txt {
		out.Grow(3 + len(s))
		if i > 0 {
			out.WriteByte(' ')
		}
		out.WriteByte('"')
		for j := 0; j < len(s); {
			b, n := nextByte(s, j)
			if n == 0 {
				break
			}
			writeTXTStringByte(&out, b)
			j += n
		}
		out.WriteByte('"')
	}
	return out.String()
}

func writeTXTStringByte(s *strings.Builder, b byte) {
	if b < ' ' || b > '~' {
		s.WriteString(escapeByte(b))
		return
	}
	if b == '"' || b == '\\' {
		s.WriteByte('\\')
	}
	s.WriteByte(b)
}

const (
	escapedByteAll = "" +
		`\000\001\002\003\004\005\006\007\008\009\010\011\012\013\014\015` +
		`\016\017\018\019\020\021\022\023\024\025\026\027\028\029\030\031` +
		`\032\033\034\035\036\037\038\039\040\041\042\043\044\045\046\047` +
		`\048\049\050\051\052\053\054\055\056\057\058\059\060\061\062\063` +
		`\064\065\066\067\068\069\070\071\072\073\074\075\076\077\078\079` +
		`\080\081\082\083\084\085\086\087\088\089\090\091\092\093\094\095` +
		`\096\097\098\099\100\101\102\103\104\105\106\107\108\109\110\111` +
		`\112\113\114\115\116\117\118\119\120\121\122\123\124\125\126\127` +
		`\128\129\130\131\132\133\134\135\136\137\138\139\140\141\142\143` +
		`\144\145\146\147\148\149\150\151\152\153\154\155\156\157\158\159` +
		`\160\161\162\163\164\165\166\167\168\169\170\171\172\173\174\175` +
		`\176\177\178\179\180\181\182\183\184\185\186\187\188\189\190\191` +
		`\192\193\194\195\196\197\198\199\200\201\202\203\204\205\206\207` +
		`\208\209\210\211\212\213\214\215\216\217\218\219\220\221\222\223` +
		`\224\225\226\227\228\229\230\231\232\233\234\235\236\237\238\239` +
		`\240\241\242\243\244\245\246\247\248\249\250\251\252\253\254\255`
)

// escapeByte returns the \DDD escaping of b which must
// satisfy b < ' ' || b > '~'.
func escapeByte(b byte) string {
	i := int(b)
	return escapedByteAll[i*4 : (i+1)*4]
}

// isDomainNameLabelSpecial returns true if
// a domain name label byte should be prefixed
// with an escaping backslash.
func isDomainNameLabelSpecial(b byte) bool {
	switch b {
	case '.', ' ', '\'', '@', ';', '(', ')', '"', '\\':
		return true
	}
	return false
}

func nextByte(s string, offset int) (byte, int) {
	if offset >= len(s) {
		return 0, 0
	}
	if s[offset] != '\\' {
		// not an escape sequence
		return s[offset], 1
	}
	switch len(s) - offset {
	case 1: // dangling escape
		return 0, 0
	case 2, 3: // too short to be \ddd
	default: // maybe \ddd
		if isDDD(s[offset+1:]) {
			return dddToByte(s[offset+1:]), 4
		}
	}
	// not \ddd, just an RFC 1035 "quoted" character
	return s[offset+1], 2
}

// SPF RR. See RFC 4408, Section 3.1.1.
type SPF struct {
	Hdr RR_Header
	Txt TxtStrings
}

// AVC RR. See https://www.iana.org/assignments/dns-parameters/AVC/avc-completed-template.
type AVC struct {
	Hdr RR_Header
	Txt TxtStrings
}

// SRV RR. See RFC 2782.
type SRV struct {
	Hdr      RR_Header
	Priority uint16
	Weight   uint16
	Port     uint16
	Target   Name
}

// NAPTR RR. See RFC 2915.
type NAPTR struct {
	Hdr         RR_Header
	Order       uint16
	Preference  uint16
	Flags       TxtString
	Service     TxtString
	Regexp      TxtString `dns:"octet"`
	Replacement Name
}

// CERT RR. See RFC 4398.
type CERT struct {
	Hdr         RR_Header
	Type        uint16
	KeyTag      uint16
	Algorithm   uint8
	Certificate ByteField `dns:"base64"`
}

func (rr *CERT) String() string {
	var (
		ok                  bool
		certtype, algorithm string
	)
	if certtype, ok = CertTypeToString[rr.Type]; !ok {
		certtype = strconv.Itoa(int(rr.Type))
	}
	if algorithm, ok = AlgorithmToString[rr.Algorithm]; !ok {
		algorithm = strconv.Itoa(int(rr.Algorithm))
	}
	return rr.Hdr.String() + certtype +
		" " + strconv.Itoa(int(rr.KeyTag)) +
		" " + algorithm +
		" " + rr.Certificate.Base64()
}

// DNAME RR. See RFC 2672.
type DNAME struct {
	Hdr    RR_Header
	Target Name
}

// A RR. See RFC 1035.
type A struct {
	Hdr RR_Header
	A   netip.Addr `dns:"a"`
}

// AAAA RR. See RFC 3596.
type AAAA struct {
	Hdr  RR_Header
	AAAA netip.Addr `dns:"aaaa"`
}

// PX RR. See RFC 2163.
type PX struct {
	Hdr        RR_Header
	Preference uint16
	Map822     Name
	Mapx400    Name
}

// GPOS RR. See RFC 1712.
type GPOS struct {
	Hdr       RR_Header
	Longitude TxtString `dns:"baretxt"`
	Latitude  TxtString `dns:"baretxt"`
	Altitude  TxtString `dns:"baretxt"`
}

// LOC RR. See RFC 1876.
type LOC struct {
	Hdr       RR_Header
	Version   uint8
	Size      uint8
	HorizPre  uint8
	VertPre   uint8
	Latitude  uint32
	Longitude uint32
	Altitude  uint32
}

// cmToM takes a cm value expressed in RFC 1876 SIZE mantissa/exponent
// format and returns a string in m (two decimals for the cm).
func cmToM(x uint8) string {
	m := x & 0xf0 >> 4
	e := x & 0x0f

	if e < 2 {
		if e == 1 {
			m *= 10
		}

		return fmt.Sprintf("0.%02d", m)
	}

	s := fmt.Sprintf("%d", m)
	for e > 2 {
		s += "0"
		e--
	}
	return s
}

func (rr *LOC) String() string {
	var b strings.Builder
	b.WriteString(rr.Hdr.String())
	lat := rr.Latitude
	ns := "N"
	if lat > LOC_EQUATOR {
		lat = lat - LOC_EQUATOR
	} else {
		ns = "S"
		lat = LOC_EQUATOR - lat
	}
	h := lat / LOC_DEGREES
	lat = lat % LOC_DEGREES
	m := lat / LOC_HOURS
	lat = lat % LOC_HOURS
	b.WriteString(fmt.Sprintf("%02d %02d %0.3f %s ", h, m, float64(lat)/1000, ns))

	lon := rr.Longitude
	ew := "E"
	if lon > LOC_PRIMEMERIDIAN {
		lon = lon - LOC_PRIMEMERIDIAN
	} else {
		ew = "W"
		lon = LOC_PRIMEMERIDIAN - lon
	}
	h = lon / LOC_DEGREES
	lon = lon % LOC_DEGREES
	m = lon / LOC_HOURS
	lon = lon % LOC_HOURS
	b.WriteString(fmt.Sprintf("%02d %02d %0.3f %s ", h, m, float64(lon)/1000, ew))

	alt := float64(rr.Altitude) / 100
	alt -= LOC_ALTITUDEBASE
	if rr.Altitude%100 != 0 {
		b.WriteString(fmt.Sprintf("%.2fm ", alt))
	} else {
		b.WriteString(fmt.Sprintf("%.0fm ", alt))
	}
	b.WriteString(cmToM(rr.Size))
	b.WriteString("m ")
	b.WriteString(cmToM(rr.HorizPre))
	b.WriteString("m ")
	b.WriteString(cmToM(rr.VertPre))
	b.WriteByte('m')
	return b.String()
}

// SIG RR. See RFC 2535. The SIG RR is identical to RRSIG and nowadays only used for SIG(0), See RFC 2931.
type SIG struct {
	RRSIG
}

// RRSIG RR. See RFC 4034 and RFC 3755.
type RRSIG struct {
	Hdr         RR_Header
	TypeCovered Type
	Algorithm   uint8
	Labels      uint8
	OrigTtl     uint32
	Expiration  Time
	Inception   Time
	KeyTag      uint16
	SignerName  Name
	Signature   ByteField `dns:"base64"`
}

// NXT RR. See RFC 2535.
type NXT struct {
	NSEC
}

// NSEC RR. See RFC 4034 and RFC 3755.
type NSEC struct {
	Hdr        RR_Header
	NextDomain Name
	TypeBitMap TypeBitMap
}

// DLV RR. See RFC 4431.
type DLV struct{ DS }

// CDS RR. See RFC 7344.
type CDS struct{ DS }

// DS RR. See RFC 4034 and RFC 3658.
type DS struct {
	Hdr        RR_Header
	KeyTag     uint16
	Algorithm  uint8
	DigestType uint8
	Digest     ByteField `dns:"hex"`
}

// KX RR. See RFC 2230.
type KX struct {
	Hdr        RR_Header
	Preference uint16
	Exchanger  Name
}

// TA RR. See http://www.watson.org/~weiler/INI1999-19.pdf.
type TA struct {
	Hdr        RR_Header
	KeyTag     uint16
	Algorithm  uint8
	DigestType uint8
	Digest     ByteField `dns:"hex"`
}

// TALINK RR. See https://www.iana.org/assignments/dns-parameters/TALINK/talink-completed-template.
type TALINK struct {
	Hdr          RR_Header
	PreviousName Name
	NextName     Name
}

// SSHFP RR. See RFC 4255.
type SSHFP struct {
	Hdr         RR_Header
	Algorithm   uint8
	Type        uint8
	FingerPrint ByteField `dns:"hex"`
}

// KEY RR. See RFC 2535.
type KEY struct {
	DNSKEY
}

// CDNSKEY RR. See RFC 7344.
type CDNSKEY struct {
	DNSKEY
}

// DNSKEY RR. See RFC 4034 and RFC 3755.
type DNSKEY struct {
	Hdr       RR_Header
	Flags     uint16
	Protocol  uint8
	Algorithm uint8
	PublicKey ByteField `dns:"base64"`
}

// IPSECKEY RR. See RFC 4025.
type IPSECKEY struct {
	Hdr         RR_Header
	Precedence  uint8
	GatewayType uint8
	Algorithm   uint8
	GatewayAddr netip.Addr `dns:"-"` // packing/unpacking/parsing/etc handled together with GatewayHost
	GatewayHost Name       `dns:"ipsechost"`
	PublicKey   ByteField  `dns:"base64"`
}

func (rr *IPSECKEY) String() string {
	var gateway string
	switch rr.GatewayType & 0x7f {
	case IPSECGatewayIPv4, IPSECGatewayIPv6:
		gateway = rr.GatewayAddr.String()
	case IPSECGatewayHost:
		gateway = rr.GatewayHost.String()
	case IPSECGatewayNone:
		fallthrough
	default:
		gateway = "."
	}

	return rr.Hdr.String() + strconv.Itoa(int(rr.Precedence)) +
		" " + strconv.Itoa(int(rr.GatewayType)) +
		" " + strconv.Itoa(int(rr.Algorithm)) +
		" " + gateway +
		" " + rr.PublicKey.Base64()
}

// AMTRELAY RR. See RFC 8777.
type AMTRELAY struct {
	Hdr         RR_Header
	Precedence  uint8
	GatewayType uint8      // discovery is packed in here at bit 0x80
	GatewayAddr netip.Addr `dns:"-"` // packing/unpacking/parsing/etc handled together with GatewayHost
	GatewayHost Name       `dns:"amtrelayhost"`
}

func (rr *AMTRELAY) String() string {
	var gateway string
	switch rr.GatewayType & 0x7f {
	case AMTRELAYIPv4, AMTRELAYIPv6:
		gateway = rr.GatewayAddr.String()
	case AMTRELAYHost:
		gateway = rr.GatewayHost.String()
	case AMTRELAYNone:
		fallthrough
	default:
		gateway = "."
	}
	boolS := "0"
	if rr.GatewayType&0x80 == 0x80 {
		boolS = "1"
	}

	return rr.Hdr.String() + strconv.Itoa(int(rr.Precedence)) +
		" " + boolS +
		" " + strconv.Itoa(int(rr.GatewayType&0x7f)) +
		" " + gateway
}

// RKEY RR. See https://www.iana.org/assignments/dns-parameters/RKEY/rkey-completed-template.
type RKEY struct {
	Hdr       RR_Header
	Flags     uint16
	Protocol  uint8
	Algorithm uint8
	PublicKey ByteField `dns:"base64"`
}

// NSAPPTR RR. See RFC 1348.
type NSAPPTR struct {
	Hdr RR_Header
	Ptr Name
}

// NSEC3 RR. See RFC 5155.
type NSEC3 struct {
	Hdr        RR_Header
	Hash       uint8
	Flags      uint8
	Iterations uint16
	SaltLength uint8     `dns:"length"`
	Salt       ByteField `dns:"size-hex:SaltLength"`
	HashLength uint8     `dns:"length"`
	NextDomain ByteField `dns:"size-base32:HashLength"`
	TypeBitMap TypeBitMap
}

// NSEC3PARAM RR. See RFC 5155.
type NSEC3PARAM struct {
	Hdr        RR_Header
	Hash       uint8
	Flags      uint8
	Iterations uint16
	SaltLength uint8     `dns:"length"`
	Salt       ByteField `dns:"size-hex:SaltLength"`
}

// TKEY RR. See RFC 2930.
type TKEY struct {
	Hdr        RR_Header
	Algorithm  Name
	Inception  Time
	Expiration Time
	Mode       uint16
	Error      uint16
	KeySize    uint16    `dns:"length"`
	Key        ByteField `dns:"size-hex:KeySize"`
	OtherLen   uint16    `dns:"length"`
	OtherData  ByteField `dns:"size-hex:OtherLen"`
}

// RFC3597 represents an unknown/generic RR. See RFC 3597.
type RFC3597 struct {
	Hdr   RR_Header
	Rdata ByteField `dns:"hex"`
}

func (rr *RFC3597) String() string {
	// Let's call it a hack
	s := rfc3597Header(rr.Hdr)

	s += "\\# " + strconv.Itoa(rr.Rdata.EncodedLen()) + " " + rr.Rdata.Hex()
	return s
}

func rfc3597Header(h RR_Header) string {
	var s string

	s += h.Name.String() + "\t"
	s += strconv.FormatInt(int64(h.Ttl), 10) + "\t"
	s += "CLASS" + strconv.Itoa(int(h.Class)) + "\t"
	s += "TYPE" + strconv.Itoa(int(h.Rrtype)) + "\t"
	return s
}

// URI RR. See RFC 7553.
type URI struct {
	Hdr      RR_Header
	Priority uint16
	Weight   uint16
	Target   TxtString // rr.Target to be parsed as a sequence of character encoded octets according to RFC 3986
}

// DHCID RR. See RFC 4701.
type DHCID struct {
	Hdr    RR_Header
	Digest ByteField `dns:"base64"`
}

// TLSA RR. See RFC 6698.
type TLSA struct {
	Hdr          RR_Header
	Usage        uint8
	Selector     uint8
	MatchingType uint8
	Certificate  ByteField `dns:"hex"`
}

// SMIMEA RR. See RFC 8162.
type SMIMEA struct {
	Hdr          RR_Header
	Usage        uint8
	Selector     uint8
	MatchingType uint8
	Certificate  ByteField `dns:"hex"`
}

func (rr *SMIMEA) String() string {
	s := rr.Hdr.String() +
		strconv.Itoa(int(rr.Usage)) +
		" " + strconv.Itoa(int(rr.Selector)) +
		" " + strconv.Itoa(int(rr.MatchingType))

	// Every Nth char needs a space on this output. If we output
	// this as one giant line, we can't read it can in because in some cases
	// the cert length overflows scan.maxTok (2048).
	sx := splitN(rr.Certificate.Hex(), 1024) // conservative value here
	s += " " + strings.Join(sx, " ")
	return s
}

// HIP RR. See RFC 8005.
type HIP struct {
	Hdr                RR_Header
	HitLength          uint8 `dns:"length"`
	PublicKeyAlgorithm uint8
	PublicKeyLength    uint16    `dns:"length"`
	Hit                ByteField `dns:"size-hex:HitLength"`
	PublicKey          ByteField `dns:"size-base64:PublicKeyLength"`
	RendezvousServers  []Name    `dns:"domain-name"`
}

// NINFO RR. See https://www.iana.org/assignments/dns-parameters/NINFO/ninfo-completed-template.
type NINFO struct {
	Hdr    RR_Header
	ZSData TxtStrings
}

// NID RR. See RFC 6742.
type NID struct {
	Hdr        RR_Header
	Preference uint16
	NodeID     uint64
}

func (rr *NID) String() string {
	s := rr.Hdr.String() + strconv.Itoa(int(rr.Preference))
	node := fmt.Sprintf("%0.16x", rr.NodeID)
	s += " " + node[0:4] + ":" + node[4:8] + ":" + node[8:12] + ":" + node[12:16]
	return s
}

// L32 RR, See RFC 6742.
type L32 struct {
	Hdr        RR_Header
	Preference uint16
	Locator32  netip.Addr `dns:"a"`
}

// L64 RR, See RFC 6742.
type L64 struct {
	Hdr        RR_Header
	Preference uint16
	Locator64  uint64
}

func (rr *L64) String() string {
	s := rr.Hdr.String() + strconv.Itoa(int(rr.Preference))
	node := fmt.Sprintf("%0.16X", rr.Locator64)
	s += " " + node[0:4] + ":" + node[4:8] + ":" + node[8:12] + ":" + node[12:16]
	return s
}

// LP RR. See RFC 6742.
type LP struct {
	Hdr        RR_Header
	Preference uint16
	Fqdn       Name
}

// EUI48 RR. See RFC 7043.
type EUI48 struct {
	Hdr     RR_Header
	Address uint64 `dns:"eui48"`
}

// EUI64 RR. See RFC 7043.
type EUI64 struct {
	Hdr     RR_Header
	Address uint64 `dns:"eui64"`
}

// CAA RR. See RFC 6844.
type CAA struct {
	Hdr   RR_Header
	Flag  uint8
	Tag   TxtString `dns:"baretxt"`
	Value TxtString
}

// UID RR. Deprecated, IANA-Reserved.
type UID struct {
	Hdr RR_Header
	Uid uint32
}

// GID RR. Deprecated, IANA-Reserved.
type GID struct {
	Hdr RR_Header
	Gid uint32
}

// UINFO RR. Deprecated, IANA-Reserved.
type UINFO struct {
	Hdr   RR_Header
	Uinfo TxtString
}

// EID RR. See http://ana-3.lcs.mit.edu/~jnc/nimrod/dns.txt.
type EID struct {
	Hdr      RR_Header
	Endpoint ByteField `dns:"hex"`
}

// NIMLOC RR. See http://ana-3.lcs.mit.edu/~jnc/nimrod/dns.txt.
type NIMLOC struct {
	Hdr     RR_Header
	Locator ByteField `dns:"hex"`
}

// OPENPGPKEY RR. See RFC 7929.
type OPENPGPKEY struct {
	Hdr       RR_Header
	PublicKey ByteField `dns:"base64"`
}

// CSYNC RR. See RFC 7477.
type CSYNC struct {
	Hdr        RR_Header
	Serial     uint32
	Flags      uint16
	TypeBitMap TypeBitMap
}

// ZONEMD RR, from draft-ietf-dnsop-dns-zone-digest
type ZONEMD struct {
	Hdr    RR_Header
	Serial uint32
	Scheme uint8
	Hash   uint8
	Digest ByteField `dns:"hex"`
}

// RESINFO RR. See RFC 9606.
type RESINFO struct {
	Hdr RR_Header
	Txt TxtStrings
}

// APL RR. See RFC 3123.
type APL struct {
	Hdr      RR_Header
	Prefixes []APLPrefix `dns:"apl"`
}

// APLPrefix is an address prefix hold by an APL record.
type APLPrefix struct {
	Negation bool
	Network  netip.Prefix
}

// str returns presentation form of the APL prefix.
func (a *APLPrefix) str() string {
	var sb strings.Builder
	if a.Negation {
		sb.WriteByte('!')
	}

	if a.Network.Addr().Is4() {
		sb.WriteByte('1')
	} else if a.Network.Addr().Is6() {
		sb.WriteByte('2')
	}

	sb.WriteByte(':')

	sb.WriteString(a.Network.String())

	return sb.String()
}

// equals reports whether two APL prefixes are identical.
func (a *APLPrefix) equals(b *APLPrefix) bool {
	return a.Negation == b.Negation && a.Network == b.Network
}

// copy returns a copy of the APL prefix.
func (a *APLPrefix) copy() APLPrefix {
	return APLPrefix{
		Negation: a.Negation,
		Network:  a.Network,
	}
}

// len returns size of the prefix in wire format.
func (a *APLPrefix) len() int {
	// 4-byte header and the network address prefix (see Section 4 of RFC 3123)
	masked := a.Network.Masked().Addr().AsSlice()
	ret := 4 + len(masked)
	for i := len(masked) - 1; i >= 0; i-- {
		if masked[i] != 0 {
			break
		}
		ret--
	}
	return ret
}

// TimeToString translates the RRSIG's incep. and expir. times to the
// string representation used when printing the record.
// It takes serial arithmetic (RFC 1982) into account.
func TimeToString(t uint32) string {
	mod := (int64(t)-time.Now().Unix())/year68 - 1
	if mod < 0 {
		mod = 0
	}
	ti := time.Unix(int64(t)-mod*year68, 0).UTC()
	return ti.Format("20060102150405")
}

// StringToTime translates the RRSIG's incep. and expir. times from
// string values like "20110403154150" to an 32 bit integer.
// It takes serial arithmetic (RFC 1982) into account.
func StringToTime(s string) (Time, error) {
	t, err := time.Parse("20060102150405", s)
	if err != nil {
		return 0, err
	}
	mod := t.Unix()/year68 - 1
	if mod < 0 {
		mod = 0
	}
	return Time(t.Unix() - mod*year68), nil
}

// saltToString converts a NSECX salt to uppercase and returns "-" when it is empty.
func saltToString(b ByteField) string {
	if b.EncodedLen() == 0 {
		return "-"
	}
	return b.Hex()
}

func euiToString(eui uint64, bits int) (hex string) {
	switch bits {
	case 64:
		hex = fmt.Sprintf("%16.16x", eui)
		hex = hex[0:2] + "-" + hex[2:4] + "-" + hex[4:6] + "-" + hex[6:8] +
			"-" + hex[8:10] + "-" + hex[10:12] + "-" + hex[12:14] + "-" + hex[14:16]
	case 48:
		hex = fmt.Sprintf("%12.12x", eui)
		hex = hex[0:2] + "-" + hex[2:4] + "-" + hex[4:6] + "-" + hex[6:8] +
			"-" + hex[8:10] + "-" + hex[10:12]
	}
	return
}

// SplitN splits a string into N sized string chunks.
// This might become an exported function once.
func splitN(s string, n int) []string {
	if len(s) < n {
		return []string{s}
	}
	sx := []string{}
	p, i := 0, n
	for {
		if i <= len(s) {
			sx = append(sx, s[p:i])
		} else {
			sx = append(sx, s[p:])
			break

		}
		p, i = p+n, i+n
	}

	return sx
}

// Name is a DNS domain name.
type Name struct {
	// wire-format; non-printable, but can be copied and works as a key
	encoded string
}

func NameFromString(s string) (ret Name, err error) {
	buf, err := serializeName(s)
	if err != nil {
		return ret, err
	}

	ret.encoded = string(buf)
	return ret, nil
}

func NameFromWire(b []byte) (ret Name, err error) {
	if len(b) == 0 || len(b) > maxDomainNameWireOctets {
		return ret, ErrName
	}

	var off int
	for {
		labelLen := int(b[off])
		if labelLen >= 0x40 {
			return ret, ErrName
		}
		off++
		if len(b[off:]) < labelLen {
			return ret, ErrName
		}
		if labelLen == 0 {
			break
		}
		off += labelLen
	}
	if off != len(b) {
		return ret, ErrName
	}

	ret.encoded = string(b)
	return ret, nil
}

func NameFromLabels(labels []string) (ret Name, err error) {
	if len(labels) == 0 {
		return ret, nil
	}

	// each size indicator + null terminator
	bufLen := len(labels) + 1

	for _, label := range labels {
		labelLen := len(label)
		bufLen += labelLen
		if labelLen == 0 || labelLen > 0x40 || bufLen > maxDomainNameWireOctets {
			return ret, ErrName
		}
	}

	buf := make([]byte, bufLen)

	var off int
	for _, label := range labels {
		buf[off] = byte(len(label))
		off++
		off += copy(buf[off:], label)
	}

	ret.encoded = string(buf)
	return ret, nil
}

func (n Name) String() string {
	if n.encoded == "" {
		return ""
	}
	ret, err := deserializeName([]byte(n.encoded))
	if err != nil {
		log.Panicf("unexpected unpack error with name %s: %s", hex.EncodeToString([]byte(n.encoded)), err)
	}
	return ret
}

func (n Name) ToWire() []byte {
	return []byte(n.encoded)
}

func (n Name) Canonical() Name {
	if len(n.encoded) == 0 {
		// root zone
		return Name{encoded: "\x00"}
	}
	buf := []byte(n.encoded)
	var modified bool
	// length bytes can be 0x3f at most (below 0x41/'A'), so they can not get mangled by this
	for i, c := range buf {
		if 'A' <= c && c <= 'Z' {
			buf[i] = c + ('a' - 'A')
			modified = true
		}
	}

	if modified {
		n.encoded = string(buf)
	}

	return n
}

func (n Name) EncodedLen() int {
	return len(n.encoded)
}

func (n Name) Concat(names ...Name) (Name, error) {
	if len(names) == 0 {
		return n, nil
	}
	if n.EncodedLen() == 0 {
		return n, ErrName
	}

	totalSize := n.EncodedLen() - len(names)
	for _, name := range names {
		el := name.EncodedLen()
		if el == 0 {
			return n, ErrName
		}
		totalSize += el
	}
	buf := make([]byte, totalSize)

	var off int
	// without final null byte of each name
	off += copy(buf[off:], []byte(n.encoded)[:len(n.encoded)-1])
	for _, name := range names {
		off += copy(buf[off:], []byte(name.encoded)[:len(name.encoded)-1])
	}

	return NameFromWire(buf)
}

func (n Name) SubNames() []Name {
	return slices.Collect(n.SubNamesIt)
}

func (n Name) SubNamesIt(yield func(Name) bool) {
	var off int
	for off < len(n.encoded)-1 {
		name := Name{encoded: n.encoded[off:]}
		if !yield(name) {
			return
		}
		labelLen := int(n.encoded[off])
		off += labelLen + 1
	}
}

func check(err error) {
	if err != nil {
		log.Panic(err)
	}
}

func check1[T any](arg1 T, err error) T {
	check(err)
	return arg1
}

func mustParseName(s string) Name {
	return check1(NameFromString(s))
}

func escapeLabel(s []byte) string {
	var b strings.Builder

	for _, c := range s {
		if c < ' ' || c > '~' {
			b.WriteString(escapeByte(c))
			continue
		}
		if isDomainNameLabelSpecial(c) {
			b.WriteByte('\\')
		}
		b.WriteByte(c)
	}
	return b.String()
}

type TxtString struct {
	// single encoded txt string, without length prefix (added separately)
	encoded string
}

func serializeTxt(text string) ([]byte, error) {
	var b bytes.Buffer

	ls := len(text)
	bs := []byte(text)

	for i := 0; i < ls; {
		c := bs[i]
		switch c {
		case '\\':
			if isDDD(bs[i+1:]) {
				escaped := dddToByte(bs[i+1:])
				b.WriteByte(escaped)
				i += 4 // len(`\234`)
			} else {
				if len(bs[i:]) < 2 {
					// dangling backslash?
					return nil, ErrTxt
				}
				b.WriteByte(bs[i+1])
				i += 2 // `len(`\.`)
			}
		default:
			b.WriteByte(c)
			i++
		}

		if b.Len() > maxTxtOctets {
			return nil, ErrTxt
		}
	}

	return b.Bytes(), nil
}

func deserializeTxt(buf []byte) string {
	// assume length is compared against maxTxtOctets externally
	var b strings.Builder
	for _, c := range buf {
		if c < ' ' || c > '~' {
			b.WriteString(escapeByte(c))
			continue
		}
		if c == '"' || c == '\\' {
			b.WriteByte('\\')
		}
		b.WriteByte(c)
	}

	return b.String()
}

func deserializeOctet(buf []byte) string {
	var b strings.Builder
	for _, c := range buf {
		if c < ' ' || c > '~' {
			b.WriteString(escapeByte(c))
			continue
		}
		if c == '"' {
			b.WriteByte('\\')
		}
		b.WriteByte(c)
	}

	return b.String()
}

func serializeOctet(s string) ([]byte, error) {
	var b bytes.Buffer

	ls := len(s)
	bs := []byte(s)

	for i := 0; i < ls; {
		c := bs[i]
		switch c {
		case '\\':
			if isDDD(bs[i+1:]) {
				escaped := dddToByte(bs[i+1:])
				b.WriteByte(escaped)
				i += 4 // len(`\234`)
			} else if len(bs[i:]) > 1 && bs[i+1] == '"' {
				// special case for `\"`
				b.WriteByte(bs[i+1])
				i += 2
			} else {
				b.WriteByte(c)
				i++
			}
		default:
			b.WriteByte(c)
			i++
		}

		if b.Len() > maxTxtOctets {
			return nil, ErrTxt
		}
	}

	return b.Bytes(), nil
}

func TxtFromString(s string) (TxtString, error) {
	var ret TxtString
	encoded, err := serializeTxt(s)
	if err == nil {
		ret.encoded = string(encoded)
	}
	return ret, err
}

func mustParseTxt(s string) TxtString {
	return check1(TxtFromString(s))
}

func mustParseTxts(arr ...string) TxtStrings {
	txts := make([]TxtString, len(arr))
	for i, v := range arr {
		txts[i] = mustParseTxt(v)
	}

	return TxtStringsFromArr(txts)
}

func TxtFromBytes(b []byte) (TxtString, error) {
	var ret TxtString
	if len(b) > 255 {
		return ret, ErrTxt
	}
	ret.encoded = string(b)
	return ret, nil
}

func TxtFromOctet(s string) (TxtString, error) {
	var ret TxtString
	buf, err := serializeOctet(s)
	if err == nil {
		ret.encoded = string(buf)
	}
	return ret, err
}

func (t TxtString) EncodedLen() int {
	return len(t.encoded) + 1
}

func (t TxtString) ToWire() []byte {
	ret := make([]byte, t.EncodedLen())
	ret[0] = byte(len(t.encoded))
	copy(ret[1:], []byte(t.encoded))
	return ret
}

func (t TxtString) BareString() string {
	return deserializeTxt([]byte(t.encoded))
}

func (t TxtString) String() string {
	var b strings.Builder
	b.WriteByte('"')
	b.WriteString(t.BareString())
	b.WriteByte('"')
	return b.String()
}

func (t TxtString) OctetString() string {
	var b strings.Builder
	b.WriteByte('"')
	b.WriteString(deserializeOctet([]byte(t.encoded)))
	b.WriteByte('"')
	return b.String()
}

type TxtStrings struct {
	// length prefix encoded TxtStrings
	encoded string
}

func TxtStringsFromArr(arr []TxtString) TxtStrings {
	buflen := len(arr)
	for _, e := range arr {
		buflen += len(e.encoded)
	}

	buf := make([]byte, buflen)

	var off int
	for _, e := range arr {
		buf[off] = byte(len(e.encoded))
		off++
		off += copy(buf[off:], []byte(e.encoded))
	}

	return TxtStrings{encoded: string(buf)}
}

func (t TxtStrings) EncodedLen() int {
	return len(t.encoded)
}

func (t TxtStrings) Split() []TxtString {
	return slices.Collect((t.SplitIt))
}

func (t TxtStrings) SplitStr() []string {
	return slices.Collect(t.SplitStrIt)
}

func (t TxtStrings) SplitStrIt(yield func(string) bool) {
	for e := range t.SplitIt {
		if !yield(e.BareString()) {
			return
		}
	}
}

func (t TxtStrings) SplitIt(yield func(TxtString) bool) {
	var off int
	for off < len(t.encoded) {
		txtLen := int(t.encoded[off])
		off++
		e := TxtString{t.encoded[off : off+txtLen]}
		if !yield(e) {
			return
		}
		off += txtLen
	}
}

func (t TxtStrings) String() string {
	var b strings.Builder

	var i int
	for e := range t.SplitIt {
		if i > 0 {
			b.WriteByte(' ')
		}
		i++
		b.WriteString(e.String())
	}

	return b.String()
}

func (t TxtStrings) BareString() string {
	var b strings.Builder

	for e := range t.SplitIt {
		b.WriteString(e.BareString())
	}

	return b.String()
}

type ByteField struct {
	raw string
}

func BFFromBytes(b []byte) ByteField {
	return ByteField{raw: string(b)}
}

func BFFromHex(s string) (ByteField, error) {
	var ret ByteField
	buf, err := hex.DecodeString(s)
	if err == nil {
		ret.raw = string(buf)
	}
	return ret, err
}

func BFFromBase64(s string) (ByteField, error) {
	var ret ByteField
	buf, err := base64.StdEncoding.DecodeString(s)
	if err == nil {
		ret.raw = string(buf)
	}
	return ret, err
}

func BFFromBase32(s string) (ByteField, error) {
	var ret ByteField
	buf, err := base32HexNoPadEncoding.DecodeString(strings.ToUpper(s))
	if err == nil {
		ret.raw = string(buf)
	}
	return ret, err
}

func (b ByteField) EncodedLen() int {
	return len(b.raw)
}

func (b ByteField) Hex() string {
	return strings.ToUpper(hex.EncodeToString([]byte(b.raw)))
}

func (b ByteField) Base32() string {
	return base32HexNoPadEncoding.EncodeToString([]byte(b.raw))
}

func (b ByteField) Base64() string {
	return base64.StdEncoding.EncodeToString([]byte(b.raw))
}

func (b ByteField) Raw() []byte {
	return []byte(b.raw)
}

func (b ByteField) String() string {
	return b.Hex()
}

type Time uint32

func (t Time) String() string {
	mod := max((int64(t)-time.Now().Unix())/year68-1, 0)
	ti := time.Unix(int64(t)-mod*year68, 0).UTC()
	return ti.Format("20060102150405")
}

type TypeBitMap struct {
	encoded string
}

func TBMFromList(l []Type) TypeBitMap {
	var ret TypeBitMap
	if len(l) == 0 {
		return ret
	}

	slices.Sort(l)

	var b bytes.Buffer

	var bitsWindow [32]byte
	var prevWindowLen int
	prevWindow := l[0] / 256

	for _, t := range l {
		window := t / 256
		if window > prevWindow {
			// write out prev window
			b.WriteByte(byte(prevWindow))
			b.WriteByte(byte(prevWindowLen))
			b.Write(bitsWindow[:prevWindowLen])
			prevWindow = window
			for i := range bitsWindow {
				bitsWindow[i] = 0
			}
		}

		windowData := t % 256
		windowOff := windowData / 8
		windowBit := windowData % 8

		bitsWindow[windowOff] |= 0x80 >> windowBit

		prevWindowLen = int(windowOff) + 1
	}

	// write out last window
	b.WriteByte(byte(prevWindow))
	b.WriteByte(byte(prevWindowLen))
	b.Write(bitsWindow[:prevWindowLen])

	ret.encoded = b.String()
	return ret
}

func (tbm TypeBitMap) Iter(yield func(Type) bool) {
	if len(tbm.encoded) == 0 {
		return
	}

	sb := []byte(tbm.encoded)
	var off int

	for off < len(sb) {
		window := int(sb[off])
		bitsLen := int(sb[off+1])
		off += 2
		for i, v := range sb[off : off+bitsLen] {
			if v == 0 {
				continue
			}
			for j := range 8 {
				if mask := byte(0x80 >> j); v&mask == mask {
					if t := Type(window*256 + i*8 + j); !yield(t) {
						return
					}
				}
			}
		}
		off += bitsLen
	}
}

func (tbm TypeBitMap) List() []Type {
	return slices.Collect(tbm.Iter)
}

func (tbm TypeBitMap) EncodedLen() int {
	return len(tbm.encoded)
}

func (tbm TypeBitMap) Raw() []byte {
	return []byte(tbm.encoded)
}

// space prefixed
func (tbm TypeBitMap) String() string {
	var b strings.Builder

	for t := range tbm.Iter {
		b.WriteByte(' ')
		b.WriteString(t.String())
	}

	return b.String()
}
