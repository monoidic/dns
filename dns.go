package dns

import (
	"strconv"
	"strings"
)

const (
	year68     = 1 << 31 // For RFC1982 (Serial Arithmetic) calculations in 32 bits.
	defaultTtl = 3600    // Default internal TTL.

	// DefaultMsgSize is the standard default for messages larger than 512 bytes.
	DefaultMsgSize = 4096
	// MinMsgSize is the minimal size of a DNS packet.
	MinMsgSize = 512
	// MaxMsgSize is the largest possible DNS packet.
	MaxMsgSize = 65535
)

// Error represents a DNS error.
type Error struct{ err string }

func (e *Error) Error() string {
	if e == nil {
		return "dns: <nil>"
	}
	return "dns: " + e.err
}

// An RR represents a resource record.
type RR interface {
	// Header returns the header of an resource record. The header contains
	// everything up to the rdata.
	Header() *RR_Header
	// String returns the text representation of the resource record.
	String() string

	// copy returns a copy of the RR
	copy() RR

	// len returns the length (in octets) of the compressed or uncompressed RR in wire format.
	//
	// If compression is nil, the uncompressed size will be returned, otherwise the compressed
	// size will be returned and domain names will be added to the map for future compression.
	len(off int, compression map[Name]struct{}) int

	// pack packs the records RDATA into wire format. The header will
	// already have been packed into msg.
	pack(msg []byte, off int, compression compressionMap, compress bool) (off1 int, err error)

	// unpack unpacks an RR from wire format.
	//
	// This will only be called on a new and empty RR type with only the header populated. It
	// will only be called if the record's RDATA is non-empty.
	unpack(msg []byte, off int) (off1 int, err error)

	// parse parses an RR from zone file format.
	//
	// This will only be called on a new and empty RR type with only the header populated.
	parse(c *zlexer, origin Name) *ParseError

	// isDuplicate returns whether the two RRs are duplicates.
	isDuplicate(r2 RR) bool
}

// RR_Header is the header all DNS resource records share.
type RR_Header struct {
	Name     Name `dns:"cdomain-name"`
	Rrtype   Type
	Class    Class
	Ttl      uint32
	Rdlength uint16 // Length of data after header.
}

// Header returns itself. This is here to make RR_Header implements the RR interface.
func (h *RR_Header) Header() *RR_Header { return h }

// Just to implement the RR interface.
func (h *RR_Header) copy() RR {
	panic("dns: internal error: copy should never be called on RR_Header")
}

func (h *RR_Header) String() string {
	var s strings.Builder

	switch h.Rrtype {
	case TypeOPT, TypeNULL, TypeTKEY, TypeTSIG:
		// these types have no string representation
		s.WriteByte(';')
		// and maybe other things
	}

	s.WriteString(h.Name.String())
	s.WriteByte('\t')

	s.WriteString(strconv.FormatInt(int64(h.Ttl), 10))
	s.WriteByte('\t')

	s.WriteString(Class(h.Class).String())
	s.WriteByte('\t')

	s.WriteString(Type(h.Rrtype).String())
	s.WriteByte('\t')

	return s.String()
}

func (h *RR_Header) len(off int, compression map[Name]struct{}) int {
	l := domainNameLen(h.Name, off, compression, true)
	l += 10 // rrtype(2) + class(2) + ttl(4) + rdlength(2)
	return l
}

func (h *RR_Header) pack(msg []byte, off int, compression compressionMap, compress bool) (off1 int, err error) {
	// RR_Header has no RDATA to pack.
	return off, nil
}

func (h *RR_Header) unpack(msg []byte, off int) (int, error) {
	panic("dns: internal error: unpack should never be called on RR_Header")
}

func (h *RR_Header) parse(c *zlexer, origin Name) *ParseError {
	panic("dns: internal error: parse should never be called on RR_Header")
}

// ToRFC3597 converts a known RR to the unknown RR representation from RFC 3597.
func (rr *RFC3597) ToRFC3597(r RR) error {
	buf := make([]byte, Len(r))
	headerEnd, off, err := packRR(r, buf, 0, compressionMap{}, false)
	if err != nil {
		return err
	}
	buf = buf[:off]

	*rr = RFC3597{Hdr: *r.Header()}
	rr.Hdr.Rdlength = uint16(off - headerEnd)

	if noRdata(rr.Hdr) {
		return nil
	}

	_, err = rr.unpack(buf, headerEnd)
	return err
}

// fromRFC3597 converts an unknown RR representation from RFC 3597 to the known RR type.
func (rr *RFC3597) fromRFC3597(r RR) error {
	hdr := r.Header()
	*hdr = rr.Hdr

	// Can't overflow uint16 as the length of Rdata is validated in (*RFC3597).parse.
	// We can only get here when rr was constructed with that method.
	hdr.Rdlength = uint16(rr.Rdata.EncodedLen())

	if noRdata(*hdr) {
		// Dynamic update.
		return nil
	}

	// rr.pack requires an extra allocation and a copy so we just decode Rdata
	// manually, it's simpler anyway.
	msg := rr.Rdata.Raw()

	_, err := r.unpack(msg, 0)
	return err
}
