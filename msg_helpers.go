package dns

import (
	"cmp"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"net"
	"net/netip"
	"slices"
	"strings"
)

// helper functions called from the generated zmsg.go

// These function are named after the tag to help pack/unpack, if there is no tag it is the name
// of the type they pack/unpack (string, int, etc). We prefix all with unpackData or packData, so packDataA or
// packDataDomainName.

func unpackDataA(msg []byte, off int) (netip.Addr, int, error) {
	if off+net.IPv4len > len(msg) {
		return netip.Addr{}, len(msg), &Error{err: "overflow unpacking a"}
	}
	addr, _ := netip.AddrFromSlice(msg[off : off+net.IPv4len])
	return addr, off + net.IPv4len, nil
}

func packDataA(a netip.Addr, msg []byte, off int) (int, error) {
	if !a.IsValid() {
		// Allowed, dynamic updates.
		return off, nil
	}
	if !a.Is4() {
		return len(msg), &Error{err: "invalid address"}
	}
	if off+net.IPv4len > len(msg) {
		return len(msg), &Error{err: "overflow packing a"}
	}

	off += copy(msg[off:], a.AsSlice())
	return off, nil
}

func unpackDataAAAA(msg []byte, off int) (netip.Addr, int, error) {
	if off+net.IPv6len > len(msg) {
		return netip.Addr{}, len(msg), &Error{err: "overflow unpacking aaaa"}
	}
	addr, _ := netip.AddrFromSlice(msg[off : off+net.IPv6len])
	return addr, off + net.IPv6len, nil
}

func packDataAAAA(aaaa netip.Addr, msg []byte, off int) (int, error) {
	if !aaaa.IsValid() {
		// Allowed, dynamic updates.
		return off, nil
	}
	if !aaaa.Is6() {
		return len(msg), &Error{err: "invalid address"}
	}
	if off+net.IPv6len > len(msg) {
		return len(msg), &Error{err: "overflow packing aaaa"}
	}

	off += copy(msg[off:], aaaa.AsSlice())
	return off, nil
}

// unpackHeader unpacks an RR header, returning the offset to the end of the header and a
// re-sliced msg according to the expected length of the RR.
func unpackHeader(msg []byte, off int) (rr RR_Header, off1 int, truncmsg []byte, err error) {
	hdr := RR_Header{}

	hdr.Name, off, err = UnpackDomainName(msg, off)
	if err != nil {
		return hdr, len(msg), msg, err
	}

	if len(msg[off:]) < 10 {
		return hdr, len(msg), msg, ErrBuf
	}

	hdr.Rrtype = Type(binary.BigEndian.Uint16(msg[off+0:]))
	hdr.Class = Class(binary.BigEndian.Uint16(msg[off+2:]))
	hdr.Ttl = binary.BigEndian.Uint32(msg[off+4:])
	hdr.Rdlength = binary.BigEndian.Uint16(msg[off+8:])
	off += 10

	msg, err = truncateMsgFromRdlength(msg, off, hdr.Rdlength)
	return hdr, off, msg, err
}

// packHeader packs an RR header, returning the offset to the end of the header.
// See PackDomainName for documentation about the compression.
func (hdr RR_Header) packHeader(msg []byte, off int, compression compressionMap, compress bool) (int, error) {
	off, err := packDomainName(hdr.Name, msg, off, compression, compress)
	if err != nil {
		return len(msg), err
	}

	if len(msg[off:]) < 10 {
		return len(msg), ErrBuf
	}
	binary.BigEndian.PutUint16(msg[off+0:], uint16(hdr.Rrtype))
	binary.BigEndian.PutUint16(msg[off+2:], uint16(hdr.Class))
	binary.BigEndian.PutUint32(msg[off+4:], hdr.Ttl)
	binary.BigEndian.PutUint16(msg[off+8:], 0) // The RDLENGTH field will be set later in packRR.
	off += 10
	return off, nil
}

// helper helper functions.

// truncateMsgFromRdLength truncates msg to match the expected length of the RR.
// Returns an error if msg is smaller than the expected size.
func truncateMsgFromRdlength(msg []byte, off int, rdlength uint16) (truncmsg []byte, err error) {
	lenrd := off + int(rdlength)
	if lenrd > len(msg) {
		return msg, &Error{err: "overflowing header size"}
	}
	return msg[:lenrd], nil
}

var base32HexNoPadEncoding = base32.HexEncoding.WithPadding(base32.NoPadding)

func fromBase64(s []byte) (buf []byte, err error) {
	buflen := base64.StdEncoding.DecodedLen(len(s))
	buf = make([]byte, buflen)
	n, err := base64.StdEncoding.Decode(buf, s)
	buf = buf[:n]
	return
}

func toBase64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// dynamicUpdate returns true if the Rdlength is zero.
func noRdata(h RR_Header) bool { return h.Rdlength == 0 }

func unpackUint8(msg []byte, off int) (i uint8, off1 int, err error) {
	if len(msg[off:]) < 1 {
		return 0, len(msg), &Error{err: "overflow unpacking uint8"}
	}
	return msg[off], off + 1, nil
}

func packUint8(i uint8, msg []byte, off int) (off1 int, err error) {
	if len(msg[off:]) < 1 {
		return len(msg), &Error{err: "overflow packing uint8"}
	}
	msg[off] = i
	return off + 1, nil
}

func unpackUint16(msg []byte, off int) (i uint16, off1 int, err error) {
	if len(msg[off:]) < 2 {
		return 0, len(msg), &Error{err: "overflow unpacking uint16"}
	}
	return binary.BigEndian.Uint16(msg[off:]), off + 2, nil
}

func unpackType(msg []byte, off int) (i Type, off1 int, err error) {
	ii, off1, err := unpackUint16(msg, off)
	return Type(ii), off1, err
}

func packUint16(i uint16, msg []byte, off int) (off1 int, err error) {
	if len(msg[off:]) < 2 {
		return len(msg), &Error{err: "overflow packing uint16"}
	}
	binary.BigEndian.PutUint16(msg[off:], i)
	return off + 2, nil
}

func unpackUint32(msg []byte, off int) (i uint32, off1 int, err error) {
	if len(msg[off:]) < 4 {
		return 0, len(msg), &Error{err: "overflow unpacking uint32"}
	}
	return binary.BigEndian.Uint32(msg[off:]), off + 4, nil
}

func unpackTime(msg []byte, off int) (i Time, off1 int, err error) {
	ii, off1, err := unpackUint32(msg, off)
	return Time(ii), off1, err
}

func packUint32(i uint32, msg []byte, off int) (off1 int, err error) {
	if len(msg[off:]) < 4 {
		return len(msg), &Error{err: "overflow packing uint32"}
	}
	binary.BigEndian.PutUint32(msg[off:], i)
	return off + 4, nil
}

func unpackUint48(msg []byte, off int) (i uint64, off1 int, err error) {
	if len(msg[off:]) < 6 {
		return 0, len(msg), &Error{err: "overflow unpacking uint64 as uint48"}
	}
	// Used in TSIG where the last 48 bits are occupied, so for now, assume a uint48 (6 bytes)
	i = uint64(binary.BigEndian.Uint32(msg[off:])) << 16
	i |= uint64(binary.BigEndian.Uint16(msg[off+4:]))
	off += 6
	return i, off, nil
}

func packUint48(i uint64, msg []byte, off int) (off1 int, err error) {
	if len(msg[off:]) < 6 {
		return len(msg), &Error{err: "overflow packing uint64 as uint48"}
	}
	binary.BigEndian.PutUint32(msg[off:], uint32(i>>16))
	binary.BigEndian.PutUint16(msg[off+4:], uint16(i))
	off += 6
	return off, nil
}

func unpackUint64(msg []byte, off int) (i uint64, off1 int, err error) {
	if len(msg[off:]) < 8 {
		return 0, len(msg), &Error{err: "overflow unpacking uint64"}
	}
	return binary.BigEndian.Uint64(msg[off:]), off + 8, nil
}

func packUint64(i uint64, msg []byte, off int) (off1 int, err error) {
	if len(msg[off:]) < 8 {
		return len(msg), &Error{err: "overflow packing uint64"}
	}
	binary.BigEndian.PutUint64(msg[off:], i)
	off += 8
	return off, nil
}

func unpackString(msg []byte, off int) (TxtString, int, error) {
	var ret TxtString
	if len(msg[off:]) < 1 {
		return ret, off, &Error{err: "overflow unpacking txt"}
	}
	l := int(msg[off])
	off++
	if len(msg[off:]) < l {
		return ret, off, &Error{err: "overflow unpacking txt"}
	}

	ret.encoded = string(msg[off : off+l])
	off += l
	return ret, off, nil

}

func packByteField(bf ByteField, msg []byte, off int) (int, error) {
	if len(msg[off:]) < bf.EncodedLen() {
		return len(msg), ErrBuf
	}

	off += copy(msg[off:], bf.Raw())
	return off, nil
}

func unpackByteField(msg []byte, off, end int) (ByteField, int, error) {
	var ret ByteField
	if len(msg) < end || len(msg) < off {
		return ret, len(msg), ErrBuf
	}
	ret = BFFromBytes(msg[off:end])
	return ret, end, nil
}

func unpackDataOpt(msg []byte, off int) ([]EDNS0, int, error) {
	var edns []EDNS0
	for off < len(msg) {
		if off+4 > len(msg) {
			return nil, len(msg), &Error{err: "overflow unpacking opt"}
		}
		code := binary.BigEndian.Uint16(msg[off:])
		off += 2
		optlen := binary.BigEndian.Uint16(msg[off:])
		off += 2
		if off+int(optlen) > len(msg) {
			return nil, len(msg), &Error{err: "overflow unpacking opt"}
		}
		opt := makeDataOpt(code)
		if err := opt.unpack(msg[off : off+int(optlen)]); err != nil {
			return nil, len(msg), err
		}
		edns = append(edns, opt)
		off += int(optlen)
	}
	return edns, off, nil
}

func packDataOpt(options []EDNS0, msg []byte, off int) (int, error) {
	for _, el := range options {
		b, err := el.pack()
		if err != nil || off+4 > len(msg) {
			return len(msg), &Error{err: "overflow packing opt"}
		}
		binary.BigEndian.PutUint16(msg[off:], el.Option())      // Option code
		binary.BigEndian.PutUint16(msg[off+2:], uint16(len(b))) // Length
		off += 4
		if off+len(b) > len(msg) {
			return len(msg), &Error{err: "overflow packing opt"}
		}
		// Actual data
		copy(msg[off:off+len(b)], b)
		off += len(b)
	}
	return off, nil
}

func unpackStringOctet(msg []byte, off int) (string, int, error) {
	var b strings.Builder
	for _, c := range msg[off:] {
		if c == '\\' {
			b.WriteByte('\\')
		}
		b.WriteByte(c)
	}

	if b.Len() > 256 {
		return "", 0, ErrLen
	}

	s := b.String()
	return s, len(msg), nil
}

func unpackDataNsec(msg []byte, off int) ([]Type, int, error) {
	var nsec []Type
	length, window, lastwindow := 0, 0, -1
	for off < len(msg) {
		if off+2 > len(msg) {
			return nsec, len(msg), &Error{err: "overflow unpacking NSEC(3)"}
		}
		window = int(msg[off])
		length = int(msg[off+1])
		off += 2
		if window <= lastwindow {
			// RFC 4034: Blocks are present in the NSEC RR RDATA in
			// increasing numerical order.
			return nsec, len(msg), &Error{err: "out of order NSEC(3) block in type bitmap"}
		}
		if length == 0 {
			// RFC 4034: Blocks with no types present MUST NOT be included.
			return nsec, len(msg), &Error{err: "empty NSEC(3) block in type bitmap"}
		}
		if length > 32 {
			return nsec, len(msg), &Error{err: "NSEC(3) block too long in type bitmap"}
		}
		if off+length > len(msg) {
			return nsec, len(msg), &Error{err: "overflowing NSEC(3) block in type bitmap"}
		}

		// Walk the bytes in the window and extract the type bits
		for j, b := range msg[off : off+length] {
			// Check the bits one by one, and set the type
			if b&0x80 == 0x80 {
				nsec = append(nsec, Type(window*256+j*8+0))
			}
			if b&0x40 == 0x40 {
				nsec = append(nsec, Type(window*256+j*8+1))
			}
			if b&0x20 == 0x20 {
				nsec = append(nsec, Type(window*256+j*8+2))
			}
			if b&0x10 == 0x10 {
				nsec = append(nsec, Type(window*256+j*8+3))
			}
			if b&0x8 == 0x8 {
				nsec = append(nsec, Type(window*256+j*8+4))
			}
			if b&0x4 == 0x4 {
				nsec = append(nsec, Type(window*256+j*8+5))
			}
			if b&0x2 == 0x2 {
				nsec = append(nsec, Type(window*256+j*8+6))
			}
			if b&0x1 == 0x1 {
				nsec = append(nsec, Type(window*256+j*8+7))
			}
		}
		off += length
		lastwindow = window
	}
	return nsec, off, nil
}

// typeBitMapLen is a helper function which computes the "maximum" length of
// a the NSEC Type BitMap field.
func typeBitMapLen(bitmap []Type) int {
	if len(bitmap) == 0 {
		return 0
	}
	var l int
	var lastwindow, lastlength Type
	for _, t := range bitmap {
		window := t / 256
		length := (t-window*256)/8 + 1
		if window > lastwindow && lastlength != 0 { // New window, jump to the new offset
			l += int(lastlength) + 2
			lastlength = 0
		}
		if window < lastwindow || length < lastlength {
			// packDataNsec would return Error{err: "nsec bits out of order"} here, but
			// when computing the length, we want do be liberal.
			continue
		}
		lastwindow, lastlength = window, length
	}
	l += int(lastlength) + 2
	return l
}

func packDataNsec(bitmap []Type, msg []byte, off int) (int, error) {
	if len(bitmap) == 0 {
		return off, nil
	}
	if off > len(msg) {
		return off, &Error{err: "overflow packing nsec"}
	}
	toZero := msg[off:]
	if maxLen := typeBitMapLen(bitmap); maxLen < len(toZero) {
		toZero = toZero[:maxLen]
	}
	for i := range toZero {
		toZero[i] = 0
	}
	var lastwindow, lastlength Type
	for _, t := range bitmap {
		window := t / 256
		length := (t-window*256)/8 + 1
		if window > lastwindow && lastlength != 0 { // New window, jump to the new offset
			off += int(lastlength) + 2
			lastlength = 0
		}
		if window < lastwindow || length < lastlength {
			return len(msg), &Error{err: "nsec bits out of order"}
		}
		if off+2+int(length) > len(msg) {
			return len(msg), &Error{err: "overflow packing nsec"}
		}
		// Setting the window #
		msg[off] = byte(window)
		// Setting the octets length
		msg[off+1] = byte(length)
		// Setting the bit value for the type in the right octet
		msg[off+1+int(length)] |= byte(1 << (7 - t%8))
		lastwindow, lastlength = window, length
	}
	off += int(lastlength) + 2
	return off, nil
}

func unpackDataSVCB(msg []byte, off int) ([]SVCBKeyValue, int, error) {
	var xs []SVCBKeyValue
	var code uint16
	var length uint16
	for off < len(msg) {
		if len(msg[off:]) < 4 {
			return nil, len(msg), &Error{err: "overflow unpacking SVCB"}
		}
		code = binary.BigEndian.Uint16(msg[off+0:])
		length = binary.BigEndian.Uint16(msg[off+2:])
		off += 4

		if len(msg[off:]) < int(length) {
			return nil, len(msg), &Error{err: "overflow unpacking SVCB"}
		}
		e := makeSVCBKeyValue(SVCBKey(code))
		if e == nil {
			return nil, len(msg), &Error{err: "bad SVCB key"}
		}
		if err := e.unpack(msg[off : off+int(length)]); err != nil {
			return nil, len(msg), err
		}
		if !(len(xs) == 0 || xs[len(xs)-1].Key() < e.Key()) {
			return nil, len(msg), &Error{err: "SVCB keys not in strictly increasing order"}
		}
		xs = append(xs, e)
		off += int(length)
	}
	return xs, off, nil
}

func packDataSVCB(pairs []SVCBKeyValue, msg []byte, off int) (int, error) {
	pairs = slices.Clone(pairs)
	slices.SortFunc(pairs, func(l, r SVCBKeyValue) int {
		return cmp.Compare(l.Key(), r.Key())
	})
	prev := svcb_RESERVED
	for _, el := range pairs {
		if el.Key() == prev {
			return len(msg), &Error{err: "repeated SVCB keys are not allowed"}
		}
		prev = el.Key()
		packed, err := el.pack()
		if err != nil {
			return len(msg), err
		}
		if len(msg[off:]) < 4+len(packed) {
			return len(msg), &Error{err: "overflow packing SVCB"}
		}
		binary.BigEndian.PutUint16(msg[off+0:], uint16(el.Key()))
		binary.BigEndian.PutUint16(msg[off+2:], uint16(len(packed)))
		off += 4
		copy(msg[off:off+len(packed)], packed)
		off += len(packed)
	}
	return off, nil
}

func unpackDataDomainNames(msg []byte, off, end int) ([]Name, int, error) {
	var (
		servers []Name
		s       Name
		err     error
	)
	if end > len(msg) {
		return nil, len(msg), &Error{err: "overflow unpacking domain names"}
	}
	for off < end {
		s, off, err = UnpackDomainName(msg, off)
		if err != nil {
			return servers, len(msg), err
		}
		servers = append(servers, s)
	}
	return servers, off, nil
}

func packDataDomainNames(names []Name, msg []byte, off int, compression compressionMap, compress bool) (int, error) {
	var err error
	for _, name := range names {
		off, err = packDomainName(name, msg, off, compression, compress)
		if err != nil {
			return len(msg), err
		}
	}
	return off, nil
}

func packDataApl(data []APLPrefix, msg []byte, off int) (int, error) {
	var err error
	for i := range data {
		off, err = packDataAplPrefix(&data[i], msg, off)
		if err != nil {
			return len(msg), err
		}
	}
	return off, nil
}

func packDataAplPrefix(p *APLPrefix, msg []byte, off int) (int, error) {
	if !p.Network.IsValid() {
		return len(msg), &Error{err: "unrecognized address family"}
	}

	addr := p.Network.Masked().Addr()

	var family uint16
	switch {
	case addr.Is4():
		family = 1
	case addr.Is6():
		family = 2
	default:
		return len(msg), &Error{err: "unrecognized address family"}
	}

	var n uint8
	if p.Negation {
		n = 0x80
	}

	// trim trailing zero bytes as specified in RFC3123 Sections 4.1 and 4.2.
	trimmedAddr := addr.AsSlice()
	i := len(trimmedAddr) - 1
	for ; i >= 0 && trimmedAddr[i] == 0; i-- {
	}
	trimmedAddr = trimmedAddr[:i+1]

	adflen := uint8(len(trimmedAddr))

	if len(msg[off:]) < len(trimmedAddr)+4 {
		return len(msg), &Error{err: "overflow packing APL prefix"}
	}

	binary.BigEndian.PutUint16(msg[off:], family)
	msg[off+2] = uint8(p.Network.Bits())
	msg[off+3] = n | adflen
	off += 4
	off += copy(msg[off:], trimmedAddr)

	return off, nil
}

func unpackDataApl(msg []byte, off int) ([]APLPrefix, int, error) {
	var result []APLPrefix
	for off < len(msg) {
		prefix, end, err := unpackDataAplPrefix(msg, off)
		if err != nil {
			return nil, len(msg), err
		}
		off = end
		result = append(result, prefix)
	}
	return result, off, nil
}

func unpackDataAplPrefix(msg []byte, off int) (APLPrefix, int, error) {
	if len(msg[off:]) < 4 {
		return APLPrefix{}, len(msg), &Error{err: "overflow unpacking APL prefix"}
	}

	family := binary.BigEndian.Uint16(msg[off:])
	prefix := msg[off+2]
	nlen := msg[off+3]
	off += 4

	var ip []byte
	switch family {
	case 1:
		ip = make([]byte, net.IPv4len)
	case 2:
		ip = make([]byte, net.IPv6len)
	default:
		return APLPrefix{}, len(msg), &Error{err: "unrecognized APL address family"}
	}
	if int(prefix) > 8*len(ip) {
		return APLPrefix{}, len(msg), &Error{err: "APL prefix too long"}
	}
	afdlen := int(nlen & 0x7f)
	if afdlen > len(ip) {
		return APLPrefix{}, len(msg), &Error{err: "APL length too long"}
	}
	if off+afdlen > len(msg) {
		return APLPrefix{}, len(msg), &Error{err: "overflow unpacking APL address"}
	}

	// Address MUST NOT contain trailing zero bytes per RFC3123 Sections 4.1 and 4.2.
	off += copy(ip, msg[off:off+afdlen])
	if afdlen > 0 {
		last := ip[afdlen-1]
		if last == 0 {
			return APLPrefix{}, len(msg), &Error{err: "extra APL address bits"}
		}
	}
	ipAddr, _ := netip.AddrFromSlice(ip)
	masked := netip.PrefixFrom(ipAddr, int(prefix)).Masked()
	return APLPrefix{
		Negation: (nlen & 0x80) != 0,
		Network:  masked,
	}, off, nil
}

func unpackIPSECGateway(msg []byte, off int, gatewayType uint8) (netip.Addr, Name, int, error) {
	var retAddr netip.Addr
	var retName Name
	var err error

	switch gatewayType {
	case IPSECGatewayNone: // do nothing
	case IPSECGatewayIPv4:
		retAddr, off, err = unpackDataA(msg, off)
	case IPSECGatewayIPv6:
		retAddr, off, err = unpackDataAAAA(msg, off)
	case IPSECGatewayHost:
		retName, off, err = UnpackDomainName(msg, off)
	}

	return retAddr, retName, off, err
}

func packIPSECGateway(gatewayAddr netip.Addr, gatewayString Name, msg []byte, off int, gatewayType uint8, compression compressionMap, compress bool) (int, error) {
	var err error

	switch gatewayType {
	case IPSECGatewayNone: // do nothing
	case IPSECGatewayIPv4:
		off, err = packDataA(gatewayAddr, msg, off)
	case IPSECGatewayIPv6:
		off, err = packDataAAAA(gatewayAddr, msg, off)
	case IPSECGatewayHost:
		off, err = packDomainName(gatewayString, msg, off, compression, compress)
	}

	return off, err
}
