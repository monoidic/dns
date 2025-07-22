// DNS packet assembly, see RFC 1035. Converting from - Unpack() -
// and to - Pack() - wire format.
// All the packers and unpackers take a (msg []byte, off int)
// and return (off1 int, ok bool).  If they return ok==false, they
// also return off1==len(msg), so that the next unpacker will
// also fail.  This lets us avoid checks of ok until the end of a
// packing sequence.

package dns

//go:generate go run msg_generate.go

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math/big"
	"slices"
	"strconv"
	"strings"
)

const (
	maxCompressionOffset    = 1 << 14 // We have 14 bits for the compression pointer
	maxDomainNameWireOctets = 255     // See RFC 1035 section 2.3.4
	maxTxtOctets            = 255

	// This is the maximum number of compression pointers that should occur in a
	// semantically valid message. Each label in a domain name must be at least one
	// octet and is separated by a period. The root label won't be represented by a
	// compression pointer to a compression pointer, hence the -2 to exclude the
	// smallest valid root label.
	//
	// It is possible to construct a valid message that has more compression pointers
	// than this, and still doesn't loop, by pointing to a previous pointer. This is
	// not something a well written implementation should ever do, so we leave them
	// to trip the maximum compression pointer check.
	maxCompressionPointers = (maxDomainNameWireOctets+1)/2 - 2

	// This is the maximum length of a domain name in presentation format. The
	// maximum wire length of a domain name is 255 octets (see above), with the
	// maximum label length being 63. The wire format requires one extra byte over
	// the presentation format, reducing the number of octets by 1. Each label in
	// the name will be separated by a single period, with each octet in the label
	// expanding to at most 4 bytes (\DDD). If all other labels are of the maximum
	// length, then the final label can only be 61 octets long to not exceed the
	// maximum allowed wire length.
	maxDomainNamePresentationLength = 61*4 + 1 + 63*4 + 1 + 63*4 + 1 + 63*4 + 1
)

// Errors defined in this package.
var (
	ErrAlg           error = &Error{err: "bad algorithm"}                  // ErrAlg indicates an error with the (DNSSEC) algorithm.
	ErrAuth          error = &Error{err: "bad authentication"}             // ErrAuth indicates an error in the TSIG authentication.
	ErrBuf           error = &Error{err: "buffer size too small"}          // ErrBuf indicates that the buffer used is too small for the message.
	ErrConnEmpty     error = &Error{err: "conn has no connection"}         // ErrConnEmpty indicates a connection is being used before it is initialized.
	ErrExtendedRcode error = &Error{err: "bad extended rcode"}             // ErrExtendedRcode ...
	ErrFqdn          error = &Error{err: "domain must be fully qualified"} // ErrFqdn indicates that a domain name does not have a closing dot.
	ErrId            error = &Error{err: "id mismatch"}                    // ErrId indicates there is a mismatch with the message's ID.
	ErrKeyAlg        error = &Error{err: "bad key algorithm"}              // ErrKeyAlg indicates that the algorithm in the key is not valid.
	ErrKey           error = &Error{err: "bad key"}
	ErrKeySize       error = &Error{err: "bad key size"}
	ErrLongDomain    error = &Error{err: fmt.Sprintf("domain name exceeded %d wire-format octets", maxDomainNameWireOctets)}
	ErrNoSig         error = &Error{err: "no signature found"}
	ErrPrivKey       error = &Error{err: "bad private key"}
	ErrRcode         error = &Error{err: "bad rcode"}
	ErrRdata         error = &Error{err: "bad rdata"}
	ErrRRset         error = &Error{err: "bad rrset"}
	ErrSecret        error = &Error{err: "no secrets defined"}
	ErrShortRead     error = &Error{err: "short read"}
	ErrSig           error = &Error{err: "bad signature"} // ErrSig indicates that a signature can not be cryptographically validated.
	ErrSoa           error = &Error{err: "no SOA"}        // ErrSOA indicates that no SOA RR was seen when doing zone transfers.
	ErrTime          error = &Error{err: "bad time"}      // ErrTime indicates a timing error in TSIG authentication.
	ErrLen           error = &Error{err: "message too long"}
	ErrName          error = &Error{err: "invalid name"}
	ErrTxt           error = &Error{err: "invalid txt string"}
)

// Id by default returns a 16-bit random number to be used as a message id. The
// number is drawn from a cryptographically secure random number generator.
// This being a variable the function can be reassigned to a custom function.
// For instance, to make it return a static value for testing:
//
//	dns.Id = func() uint16 { return 3 }
var Id = id

// id returns a 16 bits random number to be used as a
// message id. The random provided should be good enough.
func id() uint16 {
	var output uint16
	err := binary.Read(rand.Reader, binary.BigEndian, &output)
	if err != nil {
		panic("dns: reading random id failed: " + err.Error())
	}
	return output
}

// MsgHdr is a a manually-unpacked version of (id, bits).
type MsgHdr struct {
	Id                 uint16
	Response           bool
	Opcode             int
	Authoritative      bool
	Truncated          bool
	RecursionDesired   bool
	RecursionAvailable bool
	Zero               bool
	AuthenticatedData  bool
	CheckingDisabled   bool
	Rcode              int
}

// Msg contains the layout of a DNS message.
type Msg struct {
	MsgHdr
	Compress bool       `json:"-"` // If true, the message will be compressed when converted to wire format.
	Question []Question // Holds the RR(s) of the question section.
	Answer   []RR       // Holds the RR(s) of the answer section.
	Ns       []RR       // Holds the RR(s) of the authority section.
	Extra    []RR       // Holds the RR(s) of the additional section.
}

// ClassToString is a maps Classes to strings for each CLASS wire type.
var ClassToString = map[uint16]string{
	ClassINET:   "IN",
	ClassCSNET:  "CS",
	ClassCHAOS:  "CH",
	ClassHESIOD: "HS",
	ClassNONE:   "NONE",
	ClassANY:    "ANY",
}

// OpcodeToString maps Opcodes to strings.
var OpcodeToString = map[int]string{
	OpcodeQuery:  "QUERY",
	OpcodeIQuery: "IQUERY",
	OpcodeStatus: "STATUS",
	OpcodeNotify: "NOTIFY",
	OpcodeUpdate: "UPDATE",
}

// RcodeToString maps Rcodes to strings.
var RcodeToString = map[int]string{
	RcodeSuccess:                    "NOERROR",
	RcodeFormatError:                "FORMERR",
	RcodeServerFailure:              "SERVFAIL",
	RcodeNameError:                  "NXDOMAIN",
	RcodeNotImplemented:             "NOTIMP",
	RcodeRefused:                    "REFUSED",
	RcodeYXDomain:                   "YXDOMAIN", // See RFC 2136
	RcodeYXRrset:                    "YXRRSET",
	RcodeNXRrset:                    "NXRRSET",
	RcodeNotAuth:                    "NOTAUTH",
	RcodeNotZone:                    "NOTZONE",
	RcodeStatefulTypeNotImplemented: "DSOTYPENI",
	RcodeBadSig:                     "BADSIG", // Also known as RcodeBadVers, see RFC 6891
	//	RcodeBadVers:        "BADVERS",
	RcodeBadKey:    "BADKEY",
	RcodeBadTime:   "BADTIME",
	RcodeBadMode:   "BADMODE",
	RcodeBadName:   "BADNAME",
	RcodeBadAlg:    "BADALG",
	RcodeBadTrunc:  "BADTRUNC",
	RcodeBadCookie: "BADCOOKIE",
}

// compressionMap is used to allow a more efficient compression map
// to be used for internal packDomainName calls without changing the
// signature or functionality of public API.
//
// In particular, map[string]uint16 uses 25% less per-entry memory
// than does map[string]int.
type compressionMap struct {
	ext map[Name]int    // external callers
	int map[Name]uint16 // internal callers
}

func (m compressionMap) valid() bool {
	return !(m.int == nil && m.ext == nil)
}

func (m compressionMap) insert(s Name, pos int) {
	if m.ext != nil {
		m.ext[s] = pos
	} else {
		m.int[s] = uint16(pos)
	}
}

func (m compressionMap) find(s Name) (int, bool) {
	if m.ext != nil {
		pos, ok := m.ext[s]
		return pos, ok
	}

	pos, ok := m.int[s]
	return int(pos), ok
}

// Domain names are a sequence of counted strings
// split at the dots. They end with a zero-length string.

// PackDomainName packs a domain name s into msg[off:].
// If compression is wanted compress must be true and the compression
// map needs to hold a mapping between domain names and offsets
// pointing into msg.
func PackDomainName(s Name, msg []byte, off int, compression map[Name]int, compress bool) (off1 int, err error) {
	return packDomainName(s, msg, off, compressionMap{ext: compression}, compress)
}

// simplified for uncompressed names
func packName(n Name, msg []byte, off int) (off1 int, err error) {
	if len(msg[off:]) < len(n.encoded) {
		return len(msg), ErrBuf
	}

	off += copy(msg[off:], []byte(n.encoded))
	return off, nil
}

func serializeName(s string) ([]byte, error) {
	switch s {
	case "":
		// empty rdata?
		return nil, nil
	case ".":
		// root zone
		return []byte{0}, nil
	}

	ls := len(s)
	bs := []byte(s)
	var label, ret bytes.Buffer

	for i := 0; i < ls; {
		if label.Len() >= 0x40 {
			return nil, ErrName
		}
		c := bs[i]
		switch c {
		default: // normal character
			label.WriteByte(c)
			i++
		case '\\': // escaped
			if isDDD(bs[i+1:]) { // `\123` format escaped
				escaped := dddToByte(bs[i+1:])
				label.WriteByte(escaped)
				i += 4 // len(`\234`)
			} else { // `\.` format escaped
				if len(bs[i:]) < 2 {
					// dangling backslash?
					return nil, ErrName
				}
				label.WriteByte(bs[i+1])
				i += 2 // len(`\.`)
			}
		case '.': // label separator
			if label.Len() == 0 {
				return nil, ErrName
			}
			labelB := label.Bytes()
			ret.WriteByte(byte(len(labelB)))
			ret.Write(labelB)
			// minus 1 so it doesn't have to be checked for the final null byte write
			if ret.Len() > maxDomainNameWireOctets-1 {
				return nil, ErrName
			}
			label.Reset()
			i++
		}
	}

	if label.Len() > 0 {
		// no period at the end?
		return nil, ErrName
	}

	// final null byte
	ret.WriteByte(0)
	return ret.Bytes(), nil
}

func deserializeName(buf []byte) (string, error) {
	if len(buf) == 1 && buf[0] == 0 {
		return ".", nil
	}
	var b strings.Builder

	var off int

	for {
		if len(buf[off:]) < 1 {
			return "", ErrBuf
		}
		labelLen := int(buf[off])
		if labelLen == 0 {
			break
		}

		off++
		if len(buf[off:]) < labelLen {
			return "", ErrBuf
		}
		label := buf[off : off+labelLen]
		escaped := escapeLabel(label)
		b.WriteString(escaped)
		b.WriteByte('.')
		off += labelLen
	}

	return b.String(), nil
}

func packDomainName(s Name, msg []byte, off int, compression compressionMap, compress bool) (off1 int, err error) {
	if s.EncodedLen() == 0 { // Ok, for instance when dealing with update RR without any rdata.
		return off, nil
	}

	// no compression or root zone
	if !compression.valid() || s.encoded == "\x00" {
		return packName(s, msg, off)
	}

	nameLen := s.EncodedLen()
	for i, subname := range s.SubNames() {
		thisLen := subname.EncodedLen()
		calcOff := off + nameLen - thisLen
		ptr, foundPtr := compression.find(subname)
		if !foundPtr && calcOff < maxCompressionOffset {
			compression.insert(subname, calcOff)
		}

		if !(foundPtr && compress) {
			continue
		}

		if i > 0 {
			// write prefix labels
			prefix, err := NameFromLabels(s.SplitRaw()[:i])
			if err != nil {
				// input name expected to be valid
				panic(err)
			}
			wire := prefix.ToWire()
			// without null terminator
			wire = wire[:len(wire)-1]
			if len(msg[off:]) < len(wire) {
				return len(msg), ErrBuf
			}
			off += copy(msg[off:], wire)
		}

		// write pointer
		if len(msg[off:]) < 2 {
			return len(msg), ErrBuf
		}
		binary.BigEndian.PutUint16(msg[off:], uint16(ptr|0xC000))
		off += 2
		return off, nil
	}

	// no compression requested/found
	return packName(s, msg, off)
}

// Unpack a domain name.
// In addition to the simple sequences of counted strings above,
// domain names are allowed to refer to strings elsewhere in the
// packet, to avoid repeating common suffixes when returning
// many entries in a single domain.  The pointers are marked
// by a length byte with the top two bits set.  Ignoring those
// two bits, that byte and the next give a 14 bit offset from msg[0]
// where we should pick up the trail.
// Note that if we jump elsewhere in the packet,
// we return off1 == the offset after the first pointer we found,
// which is where the next record will start.
// In theory, the pointers are only allowed to jump backward.
// We let them jump anywhere and stop jumping after a while.

// UnpackDomainName unpacks a domain name into a string. It returns
// the name, the new offset into msg and any error that occurred.
//
// When an error is encountered, the unpacked name will be discarded
// and len(msg) will be returned as the offset.
func UnpackDomainName(msg []byte, off int) (ret Name, off1 int, err error) {
	var buf bytes.Buffer
	lenmsg := len(msg)
	budget := maxDomainNameWireOctets
	ptr := 0 // number of pointers followed
Loop:
	for {
		if off >= lenmsg {
			return ret, lenmsg, ErrBuf
		}
		c := int(msg[off])
		off++
		switch c & 0xC0 {
		case 0x00: // regular label
			if c == 0x00 {
				buf.WriteByte(0)
				// end of name
				break Loop
			}
			// literal string
			if len(msg[off:]) < c {
				return ret, lenmsg, ErrBuf
			}
			budget -= c + 1 // +1 for the label separator
			if budget <= 0 {
				return ret, lenmsg, ErrLongDomain
			}
			buf.Write(msg[off-1 : off+c])
			off += c
		case 0xC0:
			// pointer to somewhere else in msg.
			// remember location after first ptr,
			// since that's how many bytes we consumed.
			// also, don't follow too many pointers --
			// maybe there's a loop.
			if off >= lenmsg {
				return ret, lenmsg, ErrBuf
			}
			c1 := msg[off]
			off++
			if ptr == 0 {
				off1 = off
			}
			ptr++
			if ptr > maxCompressionPointers {
				return ret, lenmsg, &Error{err: "too many compression pointers"}
			}
			// pointer should guarantee that it advances and points forwards at least
			// but the condition on previous three lines guarantees that it's
			// at least loop-free
			off = (c^0xC0)<<8 | int(c1)
		default:
			// 0x80 and 0x40 are reserved
			return ret, lenmsg, ErrRdata
		}
	}
	if ptr == 0 {
		off1 = off
	}
	wire := buf.Bytes()
	if len(wire) == 0 {
		return ret, off1, nil
	}
	ret, err = NameFromWire(wire)
	if err != nil {
		off1 = len(msg)
	}
	return ret, off1, err
}

func packTxt(txt []string, msg []byte, offset int) (int, error) {
	if len(txt) == 0 {
		if offset >= len(msg) {
			return offset, ErrBuf
		}
		msg[offset] = 0
		return offset, nil
	}
	var err error
	for _, s := range txt {
		offset, err = packTxtString(s, msg, offset)
		if err != nil {
			return offset, err
		}
	}
	return offset, nil
}

func packTxtString(s string, msg []byte, offset int) (int, error) {
	lenByteOffset := offset
	offset, err := packOctetString(s, msg, offset+1)
	if err != nil {
		return offset, err
	}
	l := offset - lenByteOffset - 1
	if l > 255 {
		return offset, &Error{err: "string exceeded 255 bytes in txt"}
	}
	msg[lenByteOffset] = byte(l)
	return offset, nil
}

func packOctetString(s string, msg []byte, offset int) (int, error) {
	if len(s) == 0 {
		return offset, nil
	}
	if offset >= len(msg) || len(s) > 256*4+1 { /* If all \DDD */
		return offset, ErrBuf
	}
	for i := 0; i < len(s); i++ {
		if len(msg) <= offset {
			return offset, ErrBuf
		}
		if s[i] == '\\' {
			i++
			if i == len(s) {
				break
			}
			// check for \DDD
			if isDDD(s[i:]) {
				msg[offset] = dddToByte(s[i:])
				i += 2
			} else {
				msg[offset] = s[i]
			}
		} else {
			msg[offset] = s[i]
		}
		offset++
	}
	return offset, nil
}

func unpackTxt(msg []byte, off0 int) (ss []string, off int, err error) {
	off = off0
	var s string
	for off < len(msg) && err == nil {
		s, off, err = unpackString(msg, off)
		if err == nil {
			ss = append(ss, s)
		}
	}
	return
}

// Helpers for dealing with escaped bytes
func isDigit(b byte) bool { return b >= '0' && b <= '9' }

func isDDD[T ~[]byte | ~string](s T) bool {
	return len(s) >= 3 && isDigit(s[0]) && isDigit(s[1]) && isDigit(s[2])
}

func dddToByte[T ~[]byte | ~string](s T) byte {
	_ = s[2] // bounds check hint to compiler; see golang.org/issue/14808
	return byte((s[0]-'0')*100 + (s[1]-'0')*10 + (s[2] - '0'))
}

// Helper function for packing and unpacking
func intToBytes(i *big.Int, length int) []byte {
	buf := i.Bytes()
	if len(buf) < length {
		b := make([]byte, length)
		copy(b[length-len(buf):], buf)
		return b
	}
	return buf
}

// PackRR packs a resource record rr into msg[off:].
// See PackDomainName for documentation about the compression.
func PackRR(rr RR, msg []byte, off int, compression map[Name]int, compress bool) (off1 int, err error) {
	headerEnd, off1, err := packRR(rr, msg, off, compressionMap{ext: compression}, compress)
	if err == nil {
		// packRR no longer sets the Rdlength field on the rr, but
		// callers might be expecting it so we set it here.
		rr.Header().Rdlength = uint16(off1 - headerEnd)
	}
	return off1, err
}

func packRR(rr RR, msg []byte, off int, compression compressionMap, compress bool) (headerEnd int, off1 int, err error) {
	if rr == nil {
		return len(msg), len(msg), &Error{err: "nil rr"}
	}

	headerEnd, err = rr.Header().packHeader(msg, off, compression, compress)
	if err != nil {
		return headerEnd, len(msg), err
	}

	off1, err = rr.pack(msg, headerEnd, compression, compress)
	if err != nil {
		return headerEnd, len(msg), err
	}

	rdlength := off1 - headerEnd
	if int(uint16(rdlength)) != rdlength { // overflow
		return headerEnd, len(msg), ErrRdata
	}

	// The RDLENGTH field is the last field in the header and we set it here.
	binary.BigEndian.PutUint16(msg[headerEnd-2:], uint16(rdlength))
	return headerEnd, off1, nil
}

// UnpackRR unpacks msg[off:] into an RR.
func UnpackRR(msg []byte, off int) (rr RR, off1 int, err error) {
	h, off, msg, err := unpackHeader(msg, off)
	if err != nil {
		return nil, len(msg), err
	}

	return UnpackRRWithHeader(h, msg, off)
}

// UnpackRRWithHeader unpacks the record type specific payload given an existing
// RR_Header.
func UnpackRRWithHeader(h RR_Header, msg []byte, off int) (rr RR, off1 int, err error) {
	if newFn, ok := TypeToRR[h.Rrtype]; ok {
		rr = newFn()
		*rr.Header() = h
	} else {
		rr = &RFC3597{Hdr: h}
	}

	if off < 0 || off > len(msg) {
		return &h, off, &Error{err: "bad off"}
	}

	end := off + int(h.Rdlength)
	if end < off || end > len(msg) {
		return &h, end, &Error{err: "bad rdlength"}
	}

	if noRdata(h) {
		return rr, off, nil
	}

	off, err = rr.unpack(msg, off)
	if err != nil {
		return nil, end, err
	}
	if off != end {
		return &h, end, &Error{err: "bad rdlength"}
	}

	return rr, off, nil
}

// unpackRRslice unpacks msg[off:] into an []RR.
// If we cannot unpack the whole array, then it will return nil
func unpackRRslice(l int, msg []byte, off int) (dst1 []RR, off1 int, err error) {
	var r RR
	// Don't pre-allocate, l may be under attacker control
	var dst []RR
	for range l {
		off1 := off
		r, off, err = UnpackRR(msg, off)
		if err != nil {
			off = len(msg)
			break
		}
		// If offset does not increase anymore, l is a lie
		if off1 == off {
			break
		}
		dst = append(dst, r)
	}
	if err != nil && off == len(msg) {
		dst = nil
	}
	return dst, off, err
}

// Convert a MsgHdr to a string, with dig-like headers:
//
// ;; opcode: QUERY, status: NOERROR, id: 48404
//
// ;; flags: qr aa rd ra;
func (h *MsgHdr) String() string {
	if h == nil {
		return "<nil> MsgHdr"
	}

	var s strings.Builder
	s.WriteString(";; opcode: ")
	s.WriteString(OpcodeToString[h.Opcode])
	s.WriteString(", status: ")
	s.WriteString(RcodeToString[h.Rcode])
	s.WriteString(", id: ")
	s.WriteString(strconv.Itoa(int(h.Id)))

	s.WriteString("\n;; flags:")

	if h.Response {
		s.WriteString(" qr")
	}
	if h.Authoritative {
		s.WriteString(" aa")
	}
	if h.Truncated {
		s.WriteString(" tc")
	}
	if h.RecursionDesired {
		s.WriteString(" rd")
	}
	if h.RecursionAvailable {
		s.WriteString(" ra")
	}
	if h.Zero { // Hmm
		s.WriteString(" z")
	}
	if h.AuthenticatedData {
		s.WriteString(" ad")
	}
	if h.CheckingDisabled {
		s.WriteString(" cd")
	}

	s.WriteByte(';')
	return s.String()
}

// Pack packs a Msg: it is converted to wire format.
// If the dns.Compress is true the message will be in compressed wire format.
func (dns *Msg) Pack() (msg []byte, err error) {
	return dns.PackBuffer(nil)
}

// PackBuffer packs a Msg, using the given buffer buf. If buf is too small a new buffer is allocated.
func (dns *Msg) PackBuffer(buf []byte) (msg []byte, err error) {
	// If this message can't be compressed, avoid filling the
	// compression map and creating garbage.
	if dns.Compress && dns.isCompressible() {
		compression := make(map[Name]uint16) // Compression pointer mappings.
		return dns.packBufferWithCompressionMap(buf, compressionMap{int: compression}, true)
	}

	return dns.packBufferWithCompressionMap(buf, compressionMap{}, false)
}

// packBufferWithCompressionMap packs a Msg, using the given buffer buf.
func (dns *Msg) packBufferWithCompressionMap(buf []byte, compression compressionMap, compress bool) (msg []byte, err error) {
	if dns.Rcode < 0 || dns.Rcode > 0xFFF {
		return nil, ErrRcode
	}

	// Set extended rcode unconditionally if we have an opt, this will allow
	// resetting the extended rcode bits if they need to.
	if opt := dns.IsEdns0(); opt != nil {
		opt.SetExtendedRcode(uint16(dns.Rcode))
	} else if dns.Rcode > 0xF {
		// If Rcode is an extended one and opt is nil, error out.
		return nil, ErrExtendedRcode
	}

	// Convert convenient Msg into wire-like Header.
	var dh Header
	dh.Id = dns.Id
	dh.Bits = uint16(dns.Opcode)<<11 | uint16(dns.Rcode&0xF)
	if dns.Response {
		dh.Bits |= _QR
	}
	if dns.Authoritative {
		dh.Bits |= _AA
	}
	if dns.Truncated {
		dh.Bits |= _TC
	}
	if dns.RecursionDesired {
		dh.Bits |= _RD
	}
	if dns.RecursionAvailable {
		dh.Bits |= _RA
	}
	if dns.Zero {
		dh.Bits |= _Z
	}
	if dns.AuthenticatedData {
		dh.Bits |= _AD
	}
	if dns.CheckingDisabled {
		dh.Bits |= _CD
	}

	dh.Qdcount = uint16(len(dns.Question))
	dh.Ancount = uint16(len(dns.Answer))
	dh.Nscount = uint16(len(dns.Ns))
	dh.Arcount = uint16(len(dns.Extra))

	// We need the uncompressed length here, because we first pack it and then compress it.
	msg = buf
	uncompressedLen := msgLenWithCompressionMap(dns, nil)
	if packLen := uncompressedLen + 1; len(msg) < packLen {
		msg = make([]byte, packLen)
	}

	// Pack it in: header and then the pieces.
	off := 0
	off, err = dh.pack(msg, off, compression, compress)
	if err != nil {
		return nil, err
	}
	for _, r := range dns.Question {
		off, err = r.pack(msg, off, compression, compress)
		if err != nil {
			return nil, err
		}
	}
	for _, r := range dns.Answer {
		_, off, err = packRR(r, msg, off, compression, compress)
		if err != nil {
			return nil, err
		}
	}
	for _, r := range dns.Ns {
		_, off, err = packRR(r, msg, off, compression, compress)
		if err != nil {
			return nil, err
		}
	}
	for _, r := range dns.Extra {
		_, off, err = packRR(r, msg, off, compression, compress)
		if err != nil {
			return nil, err
		}
	}
	return msg[:off], nil
}

func (dns *Msg) unpack(dh Header, msg []byte, off int) (err error) {
	// If we are at the end of the message we should return *just* the
	// header. This can still be useful to the caller. 9.9.9.9 sends these
	// when responding with REFUSED for instance.
	if off == len(msg) {
		// reset sections before returning
		dns.Question, dns.Answer, dns.Ns, dns.Extra = nil, nil, nil, nil
		return nil
	}

	// Qdcount, Ancount, Nscount, Arcount can't be trusted, as they are
	// attacker controlled. This means we can't use them to pre-allocate
	// slices.
	dns.Question = nil
	for i := range dh.Qdcount {
		off1 := off
		var q Question
		q, off, err = unpackQuestion(msg, off)
		if err != nil {
			return err
		}
		if off1 == off { // Offset does not increase anymore, dh.Qdcount is a lie!
			dh.Qdcount = i
			break
		}
		dns.Question = append(dns.Question, q)
	}

	dns.Answer, off, err = unpackRRslice(int(dh.Ancount), msg, off)
	// The header counts might have been wrong so we need to update it
	dh.Ancount = uint16(len(dns.Answer))
	if err == nil {
		dns.Ns, off, err = unpackRRslice(int(dh.Nscount), msg, off)
	}
	// The header counts might have been wrong so we need to update it
	dh.Nscount = uint16(len(dns.Ns))
	if err == nil {
		dns.Extra, _, err = unpackRRslice(int(dh.Arcount), msg, off)
	}
	// The header counts might have been wrong so we need to update it
	dh.Arcount = uint16(len(dns.Extra))

	// Set extended Rcode
	if opt := dns.IsEdns0(); opt != nil {
		dns.Rcode |= opt.ExtendedRcode()
	}

	// TODO(miek) make this an error?
	// use PackOpt to let people tell how detailed the error reporting should be?
	// if off != len(msg) {
	//	// println("dns: extra bytes in dns packet", off, "<", len(msg))
	// }
	return err
}

// Unpack unpacks a binary message to a Msg structure.
func (dns *Msg) Unpack(msg []byte) (err error) {
	dh, off, err := unpackMsgHdr(msg, 0)
	if err != nil {
		return err
	}

	dns.setHdr(dh)
	return dns.unpack(dh, msg, off)
}

// Convert a complete message to a string with dig-like output.
func (dns *Msg) String() string {
	if dns == nil {
		return "<nil> MsgHdr"
	}
	var s strings.Builder
	s.WriteString(dns.MsgHdr.String())
	s.WriteByte(' ')
	if dns.MsgHdr.Opcode == OpcodeUpdate {
		s.WriteString("ZONE: ")
		s.WriteString(strconv.Itoa(len(dns.Question)))
		s.WriteString(", ")
		s.WriteString("PREREQ: ")
		s.WriteString(strconv.Itoa(len(dns.Answer)))
		s.WriteString(", ")
		s.WriteString("UPDATE: ")
		s.WriteString(strconv.Itoa(len(dns.Ns)))
		s.WriteString(", ")

	} else {
		s.WriteString("QUERY: ")
		s.WriteString(strconv.Itoa(len(dns.Question)))
		s.WriteString(", ")
		s.WriteString("ANSWER: ")
		s.WriteString(strconv.Itoa(len(dns.Answer)))
		s.WriteString(", ")
		s.WriteString("AUTHORITY: ")
		s.WriteString(strconv.Itoa(len(dns.Ns)))
		s.WriteString(", ")
	}
	s.WriteString("ADDITIONAL: ")
	s.WriteString(strconv.Itoa(len(dns.Extra)))
	s.WriteByte('\n')

	opt := dns.IsEdns0()
	if opt != nil {
		// OPT PSEUDOSECTION
		s.WriteString(opt.String())
		s.WriteByte('\n')
	}
	if len(dns.Question) > 0 {
		if dns.MsgHdr.Opcode == OpcodeUpdate {
			s.WriteString("\n;; ZONE SECTION:\n")
		} else {
			s.WriteString("\n;; QUESTION SECTION:\n")
		}
		for _, r := range dns.Question {
			s.WriteString(r.String())
			s.WriteByte('\n')
		}
	}
	if len(dns.Answer) > 0 {
		if dns.MsgHdr.Opcode == OpcodeUpdate {
			s.WriteString("\n;; PREREQUISITE SECTION:\n")
		} else {
			s.WriteString("\n;; ANSWER SECTION:\n")
		}
		for _, r := range dns.Answer {
			if r != nil {
				s.WriteString(r.String())
				s.WriteByte('\n')
			}
		}
	}
	if len(dns.Ns) > 0 {
		if dns.MsgHdr.Opcode == OpcodeUpdate {
			s.WriteString("\n;; UPDATE SECTION:\n")
		} else {
			s.WriteString("\n;; AUTHORITY SECTION:\n")
		}
		for _, r := range dns.Ns {
			if r != nil {
				s.WriteString(r.String())
				s.WriteByte('\n')
			}
		}
	}
	if len(dns.Extra) > 0 && (opt == nil || len(dns.Extra) > 1) {
		s.WriteString("\n;; ADDITIONAL SECTION:\n")
		for _, r := range dns.Extra {
			if r != nil && r.Header().Rrtype != TypeOPT {
				s.WriteString(r.String())
				s.WriteByte('\n')
			}
		}
	}
	return s.String()
}

// isCompressible returns whether the msg may be compressible.
func (dns *Msg) isCompressible() bool {
	// If we only have one question, there is nothing we can ever compress.
	return len(dns.Question) > 1 || len(dns.Answer) > 0 ||
		len(dns.Ns) > 0 || len(dns.Extra) > 0
}

// Len returns the message length when in (un)compressed wire format.
// If dns.Compress is true compression it is taken into account. Len()
// is provided to be a faster way to get the size of the resulting packet,
// than packing it, measuring the size and discarding the buffer.
func (dns *Msg) Len() int {
	// If this message can't be compressed, avoid filling the
	// compression map and creating garbage.
	if dns.Compress && dns.isCompressible() {
		compression := make(map[Name]struct{})
		return msgLenWithCompressionMap(dns, compression)
	}

	return msgLenWithCompressionMap(dns, nil)
}

func msgLenWithCompressionMap(dns *Msg, compression map[Name]struct{}) int {
	l := headerSize

	for _, r := range dns.Question {
		l += r.len(l, compression)
	}
	for _, r := range dns.Answer {
		if r != nil {
			l += r.len(l, compression)
		}
	}
	for _, r := range dns.Ns {
		if r != nil {
			l += r.len(l, compression)
		}
	}
	for _, r := range dns.Extra {
		if r != nil {
			l += r.len(l, compression)
		}
	}

	return l
}

func domainNameLen(s Name, off int, compression map[Name]struct{}, compress bool) int {
	// empty rdata or root zone
	if s.EncodedLen() == 0 || s.encoded == "\x00" {
		return 1
	}

	if compression != nil && (compress || off < maxCompressionOffset) {
		// compressionLenSearch will insert the entry into the compression
		// map if it doesn't contain it.
		if l, ok := compressionLenSearch(compression, s, off); ok && compress {

			return l + 2
		}
	}

	return s.EncodedLen()
}

func escapedNameLen(s string) int {
	nameLen := len(s)
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' {
			continue
		}

		if isDDD(s[i+1:]) {
			nameLen -= 3
			i += 3
		} else {
			nameLen--
			i++
		}
	}

	return nameLen
}

func compressionLenSearch(c map[Name]struct{}, s Name, msgOff int) (int, bool) {
	for _, name := range s.SubNames() {
		off := s.EncodedLen() - name.EncodedLen()
		if _, ok := c[name]; ok {
			return off, true
		}

		if msgOff+off < maxCompressionOffset {
			c[name] = struct{}{}
		}
	}

	return 0, false
}

// Copy returns a new RR which is a deep-copy of r.
func Copy(r RR) RR { return r.copy() }

// Len returns the length (in octets) of the uncompressed RR in wire format.
func Len(r RR) int { return r.len(0, nil) }

// Copy returns a new *Msg which is a deep-copy of dns.
func (dns *Msg) Copy() *Msg { return dns.CopyTo(new(Msg)) }

// CopyTo copies the contents to the provided message using a deep-copy and returns the copy.
func (dns *Msg) CopyTo(r1 *Msg) *Msg {
	r1.MsgHdr = dns.MsgHdr
	r1.Compress = dns.Compress

	if len(dns.Question) > 0 {
		// TODO(miek): Question is an immutable value, ok to do a shallow-copy
		r1.Question = slices.Clone(dns.Question)
	}

	rrArr := make([]RR, len(dns.Answer)+len(dns.Ns)+len(dns.Extra))
	r1.Answer, rrArr = rrArr[:len(dns.Answer):len(dns.Answer)], rrArr[len(dns.Answer):]
	r1.Ns, rrArr = rrArr[:len(dns.Ns):len(dns.Ns)], rrArr[len(dns.Ns):]
	r1.Extra = rrArr[:len(dns.Extra):len(dns.Extra)]

	for i, r := range dns.Answer {
		r1.Answer[i] = r.copy()
	}

	for i, r := range dns.Ns {
		r1.Ns[i] = r.copy()
	}

	for i, r := range dns.Extra {
		r1.Extra[i] = r.copy()
	}

	return r1
}

func (q *Question) pack(msg []byte, off int, compression compressionMap, compress bool) (int, error) {
	off, err := packDomainName(q.Name, msg, off, compression, compress)
	if err != nil {
		return off, err
	}
	if len(msg[off:]) < 4 {
		return len(msg), ErrBuf
	}
	binary.BigEndian.PutUint16(msg[off+0:], q.Qtype)
	binary.BigEndian.PutUint16(msg[off+2:], q.Qclass)
	off += 4
	return off, nil
}

func unpackQuestion(msg []byte, off int) (Question, int, error) {
	var (
		q   Question
		err error
	)
	q.Name, off, err = UnpackDomainName(msg, off)
	if err != nil {
		return q, off, fmt.Errorf("bad question name: %w", err)
	}

	if len(msg[off:]) < 4 {
		return q, len(msg), ErrBuf
	}
	q.Qtype = binary.BigEndian.Uint16(msg[off+0:])
	q.Qclass = binary.BigEndian.Uint16(msg[off+2:])
	off += 4

	return q, off, nil
}

func (dh *Header) pack(msg []byte, off int, compression compressionMap, compress bool) (int, error) {
	if len(msg[off:]) < 12 {
		return len(msg), ErrBuf
	}

	binary.BigEndian.PutUint16(msg[off+0:], dh.Id)
	binary.BigEndian.PutUint16(msg[off+2:], dh.Bits)
	binary.BigEndian.PutUint16(msg[off+4:], dh.Qdcount)
	binary.BigEndian.PutUint16(msg[off+6:], dh.Ancount)
	binary.BigEndian.PutUint16(msg[off+8:], dh.Nscount)
	binary.BigEndian.PutUint16(msg[off+10:], dh.Arcount)
	off += 12

	return off, nil
}

func unpackMsgHdr(msg []byte, off int) (Header, int, error) {
	var dh Header

	if len(msg[off:]) < 12 {
		return dh, len(msg), ErrBuf
	}

	dh.Id = binary.BigEndian.Uint16(msg[off+0:])
	dh.Bits = binary.BigEndian.Uint16(msg[off+2:])
	dh.Qdcount = binary.BigEndian.Uint16(msg[off+4:])
	dh.Ancount = binary.BigEndian.Uint16(msg[off+6:])
	dh.Nscount = binary.BigEndian.Uint16(msg[off+8:])
	dh.Arcount = binary.BigEndian.Uint16(msg[off+10:])
	off += 12

	return dh, off, nil
}

// setHdr set the header in the dns using the binary data in dh.
func (dns *Msg) setHdr(dh Header) {
	dns.Id = dh.Id
	dns.Response = dh.Bits&_QR != 0
	dns.Opcode = int(dh.Bits>>11) & 0xF
	dns.Authoritative = dh.Bits&_AA != 0
	dns.Truncated = dh.Bits&_TC != 0
	dns.RecursionDesired = dh.Bits&_RD != 0
	dns.RecursionAvailable = dh.Bits&_RA != 0
	dns.Zero = dh.Bits&_Z != 0 // _Z covers the zero bit, which should be zero; not sure why we set it to the opposite.
	dns.AuthenticatedData = dh.Bits&_AD != 0
	dns.CheckingDisabled = dh.Bits&_CD != 0
	dns.Rcode = int(dh.Bits & 0xF)
}
