package dns

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

func randBytesToMsg(msg []byte) (buf []byte, rr RR, ok bool) {
	timer := time.AfterFunc(3*time.Second, func() {
		panic("deadlocked!")
	})
	defer timer.Stop()

	if l := len(msg) - 2; !(0 < l && l < 65535) {
		return nil, nil, false
	}
	msgx := make([]byte, len(msg)+9)
	// keep name as "."
	copy(msgx[1:3], msg[:2]) // rrtype
	// keep class (2 bytes) and ttl (4 bytes) as 0
	binary.BigEndian.PutUint16(msgx[9:11], uint16(len(msg)-2)) // rdlength

	copy(msgx[11:], msg[2:]) // data
	msg = msgx

	rr, msgOff, err := UnpackRR(msg, 0)
	if err != nil {
		// oh well, does not parse
		return nil, nil, false
	}

	msg = msg[:msgOff]
	return msg, rr, true
}

func FuzzPackUnpack(f *testing.F) {
	f.Fuzz(func(t *testing.T, msg []byte) {
		timer := time.AfterFunc(3*time.Second, func() {
			panic("deadlocked!")
		})
		defer timer.Stop()

		msg, rr, ok := randBytesToMsg(msg)
		if !ok {
			return
		}

		if rr.Header().Rdlength == 0 {
			// urgh
			return
		}

		expectedLen := Len(rr)
		buf := make([]byte, expectedLen)
		bufOff, err := PackRR(rr, buf, 0, nil, false)

		if err != nil {
			t.Fatalf("error repacking: %s\n%s\n%s\nexpectedLen %d", err, rr, hex.EncodeToString(msg), expectedLen)
		}

		if expectedLen != bufOff {
			t.Fatalf("len mismatch, expected %d, got %d\n%s\n%s\n%s", expectedLen, bufOff, rr, hex.EncodeToString(msg), hex.EncodeToString(buf[:bufOff]))
		}

		rr2, rr2Off, err := UnpackRR(buf, 0)
		if err != nil {
			t.Fatalf("error on second unpack: %s\n%s\n%s", err, hex.EncodeToString(msg), hex.EncodeToString(buf[:bufOff]))
		}

		if rr2Off > expectedLen {
			t.Fatalf("lenx mismatch; expected %d, got %d\n%s\n%s\n%s\n%s", expectedLen, rr2Off, rr, rr2, hex.EncodeToString(msg), hex.EncodeToString(buf[:bufOff]))
		}

		if !IsDuplicate(rr, rr2) {
			var secondaryPass bool
			switch rr.(type) {
			case *OPT:
				// just ignore, always returns false
				secondaryPass = true
			}

			if !secondaryPass {
				t.Fatalf("rr mismatch\n%s\n%s\n%s\n%s\n%d\n", rr, rr2, hex.EncodeToString(msg), hex.EncodeToString(buf[:bufOff]), bufOff)
			}
		}
	})
}

const alphanumeric = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func containsNonAlphanumeric(s string) bool {
	return len(strings.Trim(s, alphanumeric)) > 0
}

func isEmptyString(s string) bool {
	return len(strings.Trim(s, " ")) == 0
}

// contains a laundry list of bad RR values...
func FuzzToFromString(f *testing.F) {
	f.Fuzz(func(t *testing.T, msg []byte) {
		timer := time.AfterFunc(3*time.Second, func() {
			panic("deadlocked!")
		})
		defer timer.Stop()

		msg, rr, ok := randBytesToMsg(msg)
		if !ok {
			return
		}

		switch rr.(type) {
		case *NULL, *TKEY, *TSIG, *OPT:
			// no string representation
			return
		}

		rrS := rr.String()
		rr2, err := NewRR(rrS)

		if err == nil && rr2 == nil {
			t.Fatalf("uncaught successful nil parse for %s", rr)
		}

		if err != nil {
			// no real way to parse a missing bare string/hex/base64

			switch rrT := rr.(type) {
			case *CAA:
				// TODO(monoidic) dnspython rejects non-alphanumeric strings
				if containsNonAlphanumeric(rrT.Tag.BareString()) {
					return
				}
				if isEmptyString(rrT.Tag.BareString()) {
					return
				}
			case *HIP:
				if rrT.Hit.EncodedLen() == 0 || rrT.PublicKey.EncodedLen() == 0 {
					return
				}
			case *LOC:
				// invalid coordinates accepted from binary data...
				// check for degrees >= 90
				// > or >=? idk, dnspython balked on the following:
				// dns.rdata.from_wire(dns.rdataclass.IN, dns.rdatatype.LOC, bytes.fromhex('00303030935830307830303030303030'), 0, 16, None)
				lat := rrT.Latitude
				if lat > LOC_EQUATOR {
					lat = lat - LOC_EQUATOR
				} else {
					lat = LOC_EQUATOR - lat
				}
				h := lat / LOC_DEGREES
				if h >= 90 {
					return
				}

				lon := rrT.Longitude
				if lon > LOC_PRIMEMERIDIAN {
					lon = lon - LOC_PRIMEMERIDIAN
				} else {
					lon = LOC_PRIMEMERIDIAN - lon
				}
				h = lon / LOC_DEGREES
				if h >= 90 {
					return
				}

				// SIZE format is (i & 0xf0)>>8 as base, (i & 0xf) as mantissa, e.g 0x15 == 1e5;
				// however, each nibble can only be 0x9 at most
				for _, i := range []uint8{rrT.Size, rrT.HorizPre, rrT.VertPre} {
					if (i>>4) > 9 || i&0xf > 9 {
						return
					}
				}
			case *NSEC3:
				if len(rrT.NextDomain.Raw()) == 0 {
					return
				}
			case *X25:
				addr := rrT.PSDNAddress.BareString()
				if containsNonAlphanumeric(addr) {
					return
				}
				if isEmptyString(addr) {
					return
				}
			case *GPOS:
				// wtf is this RRtype
				for _, s := range []TxtString{rrT.Longitude, rrT.Latitude, rrT.Altitude} {
					if _, err := strconv.ParseFloat(s.BareString(), 64); err != nil {
						return
					}
				}
			case *NAPTR:
				regexp := rrT.Regexp.BareString()
				if strings.ContainsAny(regexp, "\"\\") {
					// figure out better string handling for this at some point
					return
				}
			}
			t.Fatalf("rr failed parsing/unparsing %s: %s\n%s", hex.EncodeToString(msg), err, rrS)
		}

		if !IsDuplicate(rr, rr2) {
			// SVCB stuff
			switch rrT := rr.(type) {
			case *SVCB, *HTTPS:
				var keyValues []SVCBKeyValue
				switch rrTT := rrT.(type) {
				case *SVCB:
					keyValues = rrTT.Value
				case *HTTPS:
					keyValues = rrTT.Value
				}

				for _, kv := range keyValues {
					switch kvT := kv.(type) {
					case *SVCBMandatory:
						if slices.Contains(kvT.Code, svcb_RESERVED) {
							return
						}
					}
				}
			}

			switch rrT := rr.(type) {
			case *NSEC3:
				if rrT.NextDomain.EncodedLen() == 0 {
					return
				}
				// HashLength is hardcoded to 20 in parse
				rrT.HashLength = 20
				if IsDuplicate(rr, rr2) {
					return
				}
			case *X25:
				if containsNonAlphanumeric(rrT.PSDNAddress.BareString()) {
					return
				}
			case *LOC:
				// hardcoded to 0 in parse
				rrT.Version = 0
				if IsDuplicate(rr, rr2) {
					return
				}
				rr2T := rr2.(*LOC)
				f1 := []uint32{rrT.Altitude, rrT.Latitude, rrT.Longitude}
				f2 := []uint32{rr2T.Altitude, rr2T.Latitude, rr2T.Longitude}

				allDiffsSmall := true

				for i, v := range f1 {
					v2 := f2[i]
					diff := int(v) - int(v2)
					if diff < 0 {
						diff = -diff
					}
					if diff > 2 {
						allDiffsSmall = false
						break
					}
				}
				if allDiffsSmall {
					// probably just a floating point error
					return
				}
				return
			case *CAA:
				if containsNonAlphanumeric(rrT.Tag.BareString()) {
					return
				}
			case *GPOS:
				for _, s := range []TxtString{rrT.Longitude, rrT.Latitude, rrT.Altitude} {
					bare := s.BareString()
					if containsNonAlphanumeric(bare) {
						return
					}
				}
			case *NAPTR:
				regexp := rrT.Regexp.BareString()
				if strings.ContainsAny(regexp, "\"\\") {
					// figure out better string handling for this at some point
					return
				}

			}
			t.Fatalf("rr mismatch between:\n%s\n%s\n(%s)", rr, rr2, hex.EncodeToString(msg))
		}
	})
}

// just check for crashes lol
func FuzzFromString(f *testing.F) {
	f.Fuzz(func(t *testing.T, typNum uint16, rrdata string) {
		typS, ok := TypeToString[Type(typNum)]
		if !ok {
			return
		}

		msg := fmt.Sprintf(".\t0\tIN\t%s\t%s", typS, rrdata)

		timer := time.AfterFunc(3*time.Second, func() {
			panic("deadlocked!")
		})
		defer timer.Stop()

		NewRR(msg)
	})
}

// TODO fuzz string parsing too

func TestPackUnpack(t *testing.T) {
	out := new(Msg)
	out.Answer = make([]RR, 1)
	key := &DNSKEY{Flags: 257, Protocol: 3, Algorithm: RSASHA1}
	key.Hdr = RR_Header{Name: mustParseName("miek.nl."), Rrtype: TypeDNSKEY, Class: ClassINET, Ttl: 3600}
	key.PublicKey = check1(BFFromBase64("AwEAAaHIwpx3w4VHKi6i1LHnTaWeHCL154Jug0Rtc9ji5qwPXpBo6A5sRv7cSsPQKPIwxLpyCrbJ4mr2L0EPOdvP6z6YfljK2ZmTbogU9aSU2fiq/4wjxbdkLyoDVgtO+JsxNN4bjr4WcWhsmk1Hg93FV9ZpkWb0Tbad8DFqNDzr//kZ"))

	out.Answer[0] = key
	msg, err := out.Pack()
	if err != nil {
		t.Error("failed to pack msg with DNSKEY")
	}
	in := new(Msg)
	if in.Unpack(msg) != nil {
		t.Error("failed to unpack msg with DNSKEY")
	}

	sig := &RRSIG{
		TypeCovered: TypeDNSKEY, Algorithm: RSASHA1, Labels: 2,
		OrigTtl: 3600, Expiration: 4000, Inception: 4000, KeyTag: 34641, SignerName: key.Hdr.Name,
		Signature: check1(BFFromBase64("AwEAAaHIwpx3w4VHKi6i1LHnTaWeHCL154Jug0Rtc9ji5qwPXpBo6A5sRv7cSsPQKPIwxLpyCrbJ4mr2L0EPOdvP6z6YfljK2ZmTbogU9aSU2fiq/4wjxbdkLyoDVgtO+JsxNN4bjr4WcWhsmk1Hg93FV9ZpkWb0Tbad8DFqNDzr//kZ")),
	}
	sig.Hdr = RR_Header{Name: key.Hdr.Name, Rrtype: TypeRRSIG, Class: ClassINET, Ttl: 3600}

	out.Answer[0] = sig
	msg, err = out.Pack()
	if err != nil {
		t.Error("failed to pack msg with RRSIG")
	}

	if in.Unpack(msg) != nil {
		t.Error("failed to unpack msg with RRSIG")
	}
}

func TestPackUnpack2(t *testing.T) {
	m := new(Msg)
	m.Extra = make([]RR, 1)
	m.Answer = make([]RR, 1)
	dom := mustParseName("miek.nl.")
	rr := new(A)
	rr.Hdr = RR_Header{Name: dom, Rrtype: TypeA, Class: ClassINET, Ttl: 0}
	rr.A = netip.AddrFrom4([4]byte{127, 0, 0, 1})

	x := new(TXT)
	x.Hdr = RR_Header{Name: dom, Rrtype: TypeTXT, Class: ClassINET, Ttl: 0}
	x.Txt = mustParseTxts("heelalaollo")

	m.Extra[0] = x
	m.Answer[0] = rr
	_, err := m.Pack()
	if err != nil {
		t.Error("Packing failed: ", err)
		return
	}
}

func TestPackUnpack3(t *testing.T) {
	m := new(Msg)
	m.Extra = make([]RR, 2)
	m.Answer = make([]RR, 1)
	dom := mustParseName("miek.nl.")
	rr := new(A)
	rr.Hdr = RR_Header{Name: dom, Rrtype: TypeA, Class: ClassINET, Ttl: 0}
	rr.A = netip.AddrFrom4([4]byte{127, 0, 0, 1})

	x1 := new(TXT)
	x1.Hdr = RR_Header{Name: dom, Rrtype: TypeTXT, Class: ClassINET, Ttl: 0}

	x2 := new(TXT)
	x2.Hdr = RR_Header{Name: dom, Rrtype: TypeTXT, Class: ClassINET, Ttl: 0}
	x2.Txt = mustParseTxts("heelalaollo")

	m.Extra[0] = x1
	m.Extra[1] = x2
	m.Answer[0] = rr
	b, err := m.Pack()
	if err != nil {
		t.Error("packing failed: ", err)
		return
	}

	var unpackMsg Msg
	err = unpackMsg.Unpack(b)
	if err != nil {
		t.Error("unpacking failed")
		return
	}
}

func TestBailiwick(t *testing.T) {
	yes := map[string]string{
		"miek1.nl.": "miek1.nl.",
		"miek.nl.":  "ns.miek.nl.",
		".":         "miek.nl.",
	}
	for parentS, childS := range yes {
		parent := mustParseName(parentS)
		child := mustParseName(childS)
		if !IsSubDomain(parent, child) {
			t.Errorf("%s should be child of %s", child, parent)
			t.Errorf("comparelabels %d", CompareDomainName(parent, child))
			t.Errorf("lenlabels %d %d", parent.CountLabel(), child.CountLabel())
		}
	}
	no := map[string]string{
		`www.miek.nl.`: "ns.miek.nl.",
		`m\.iek.nl.`:   "ns.miek.nl.",
		`w\.iek.nl.`:   "w.iek.nl.",
		`p\\.iek.nl.`:  "ns.p.iek.nl.", // p\\.iek.nl , literal \ in domain name
		`miek.nl.`:     ".",
	}
	for parentS, childS := range no {
		parent := mustParseName(parentS)
		child := mustParseName(childS)
		if IsSubDomain(parent, child) {
			t.Errorf("%s should not be child of %s", child, parent)
			t.Errorf("comparelabels %d", CompareDomainName(parent, child))
			t.Errorf("lenlabels %d %d", parent.CountLabel(), child.CountLabel())
		}
	}
}

func TestPackNAPTR(t *testing.T) {
	for _, n := range []string{
		`apple.com. IN NAPTR   100 50 "se" "SIP+D2U" "" _sip._udp.apple.com.`,
		`apple.com. IN NAPTR   90 50 "se" "SIP+D2T" "" _sip._tcp.apple.com.`,
		`apple.com. IN NAPTR   50 50 "se" "SIPS+D2T" "" _sips._tcp.apple.com.`,
	} {
		rr := testRR(n)
		msg := make([]byte, Len(rr))
		if off, err := PackRR(rr, msg, 0, nil, false); err != nil {
			t.Errorf("packing failed: %v", err)
			t.Errorf("length %d, need more than %d", Len(rr), off)
		}
	}
}

func TestToRFC3597(t *testing.T) {
	a := testRR("miek.nl. IN A 10.0.1.1")
	x := new(RFC3597)
	x.ToRFC3597(a)
	if x.String() != `miek.nl.	3600	CLASS1	TYPE1	\# 4 0A000101` {
		t.Errorf("string mismatch, got: %s", x)
	}

	b := testRR("miek.nl. IN MX 10 mx.miek.nl.")
	x.ToRFC3597(b)
	if x.String() != `miek.nl.	3600	CLASS1	TYPE15	\# 14 000A026D78046D69656B026E6C00` {
		t.Errorf("string mismatch, got: %s", x)
	}
}

func TestNoRdataPack(t *testing.T) {
	data := make([]byte, 1024)
	for typ, fn := range TypeToRR {
		r := fn()
		*r.Header() = RR_Header{Name: mustParseName("miek.nl."), Rrtype: typ, Class: ClassINET, Ttl: 16}
		_, err := PackRR(r, data, 0, nil, false)
		if err != nil {
			t.Errorf("failed to pack RR with zero rdata: %s: %v", TypeToString[typ], err)
		}
	}
}

func TestNoRdataUnpack(t *testing.T) {
	data := make([]byte, 1024)
	for typ, fn := range TypeToRR {
		if typ == TypeSOA || typ == TypeTSIG || typ == TypeTKEY {
			// SOA, TSIG will not be seen (like this) in dyn. updates?
			// TKEY requires length fields to be present for the Key and OtherData fields
			continue
		}
		r := fn()
		*r.Header() = RR_Header{Name: mustParseName("miek.nl."), Rrtype: typ, Class: ClassINET, Ttl: 16}
		_, err := PackRR(r, data, 0, nil, false)
		if err != nil {
			// Should always work, TestNoDataPack should have caught this
			t.Errorf("failed to pack RR: %v", err)
			continue
		}
		// *actually* make data contain no rdata
		off := Len(r.Header())
		binary.BigEndian.PutUint16(data[off-2:], 0)

		if _, _, err := UnpackRR(data[:off], 0); err != nil {
			t.Errorf("failed to unpack RR with zero rdata: %s: %v", TypeToString[typ], err)
		}
	}
}

func TestRdataOverflow(t *testing.T) {
	rr := new(RFC3597)
	rr.Hdr.Name = mustParseName(".")
	rr.Hdr.Class = ClassINET
	rr.Hdr.Rrtype = 65280
	rr.Rdata = BFFromBytes(make([]byte, 0xFFFF))
	buf := make([]byte, 0xFFFF*2)
	if _, err := PackRR(rr, buf, 0, nil, false); err != nil {
		t.Fatalf("maximum size rrdata pack failed: %v", err)
	}
	rr.Rdata = BFFromBytes(append(rr.Rdata.Raw(), 0))
	if _, err := PackRR(rr, buf, 0, nil, false); err != ErrRdata {
		t.Fatalf("oversize rrdata pack didn't return ErrRdata - instead: %v", err)
	}
}

func TestCopy(t *testing.T) {
	rr := testRR("miek.nl. 2311 IN A 127.0.0.1") // Weird TTL to avoid catching TTL
	rr1 := Copy(rr)
	if rr.String() != rr1.String() {
		t.Fatalf("Copy() failed %s != %s", rr.String(), rr1.String())
	}
}

func TestMsgCopy(t *testing.T) {
	m := new(Msg)
	m.SetQuestion(mustParseName("miek.nl."), TypeA)
	rr := testRR("miek.nl. 2311 IN A 127.0.0.1")
	m.Answer = []RR{rr}
	rr = testRR("miek.nl. 2311 IN NS 127.0.0.1.")
	m.Ns = []RR{rr}

	m1 := m.Copy()
	if m.String() != m1.String() {
		t.Fatalf("Msg.Copy() failed %s != %s", m.String(), m1.String())
	}

	m1.Answer[0] = testRR("somethingelse.nl. 2311 IN A 127.0.0.1")
	if m.String() == m1.String() {
		t.Fatalf("Msg.Copy() failed; change to copy changed template %s", m.String())
	}

	rr = testRR("miek.nl. 2311 IN A 127.0.0.2")
	m1.Answer = append(m1.Answer, rr)
	if m1.Ns[0].String() == m1.Answer[1].String() {
		t.Fatalf("Msg.Copy() failed; append changed underlying array %s", m1.Ns[0].String())
	}
}

func TestMsgPackBuffer(t *testing.T) {
	testMessages := []string{
		// news.ycombinator.com.in.escapemg.com.	IN	A, response
		"586285830001000000010000046e6577730b79636f6d62696e61746f7203636f6d02696e086573636170656d6703636f6d0000010001c0210006000100000e10002c036e7332c02103646e730b67726f6f7665736861726bc02d77ed50e600002a3000000e1000093a8000000e10",

		// news.ycombinator.com.in.escapemg.com.	IN	A, question
		"586201000001000000000000046e6577730b79636f6d62696e61746f7203636f6d02696e086573636170656d6703636f6d0000010001",

		"398781020001000000000000046e6577730b79636f6d62696e61746f7203636f6d0000010001",
	}

	for i, hexData := range testMessages {
		// we won't fail the decoding of the hex
		input, _ := hex.DecodeString(hexData)
		m := new(Msg)
		if err := m.Unpack(input); err != nil {
			t.Errorf("packet %d failed to unpack", i)
			continue
		}
	}
}

// Make sure we can decode a TKEY packet from the string, modify the RR, and then pack it again.
func TestTKEY(t *testing.T) {
	// An example TKEY RR captured.  There is no known accepted standard text format for a TKEY
	// record so we do this from a hex string instead of from a text readable string.
	tkeyStr := "0737362d6d732d370932322d3332633233332463303439663961662d633065612d313165372d363839362d6463333937396666656666640000f900ff0000000000d2086773732d747369670059fd01f359fe53730003000000b8a181b53081b2a0030a0100a10b06092a864882f712010202a2819d04819a60819706092a864886f71201020202006f8187308184a003020105a10302010fa2783076a003020112a26f046db29b1b1d2625da3b20b49dafef930dd1e9aad335e1c5f45dcd95e0005d67a1100f3e573d70506659dbed064553f1ab890f68f65ae10def0dad5b423b39f240ebe666f2886c5fe03819692d29182bbed87b83e1f9d16b7334ec16a3c4fc5ad4a990088e0be43f0c6957916f5fe60000"
	tkeyBytes, err := hex.DecodeString(tkeyStr)
	if err != nil {
		t.Fatal("unable to decode TKEY string ", err)
	}
	// Decode the RR
	rr, tkeyLen, unPackErr := UnpackRR(tkeyBytes, 0)
	if unPackErr != nil {
		t.Fatal("unable to decode TKEY RR", unPackErr)
	}
	// Make sure it's a TKEY record
	if rr.Header().Rrtype != TypeTKEY {
		t.Fatal("Unable to decode TKEY")
	}
	// Make sure we get back the same length
	if Len(rr) != len(tkeyBytes) {
		t.Fatalf("Lengths don't match %d != %d", Len(rr), len(tkeyBytes))
	}
	// make space for it with some fudge room
	msg := make([]byte, tkeyLen+1000)
	offset, packErr := PackRR(rr, msg, 0, nil, false)
	if packErr != nil {
		t.Fatal("unable to pack TKEY RR", packErr)
	}
	if offset != len(tkeyBytes) {
		t.Fatalf("mismatched TKEY RR size %d != %d", len(tkeyBytes), offset)
	}
	if !bytes.Equal(tkeyBytes, msg[0:offset]) {
		t.Fatal("mismatched TKEY data after rewriting bytes")
	}

	// Now add some bytes to this and make sure we can encode OtherData properly
	tkey := rr.(*TKEY)
	tkey.OtherData = check1(BFFromHex("abcd"))
	tkey.OtherLen = 2
	offset, packErr = PackRR(tkey, msg, 0, nil, false)
	if packErr != nil {
		t.Fatal("unable to pack TKEY RR after modification", packErr)
	}
	if offset != len(tkeyBytes)+2 {
		t.Fatalf("mismatched TKEY RR size %d != %d", offset, len(tkeyBytes)+2)
	}

	// Make sure we can parse our string output
	tkey.Hdr.Class = ClassINET // https://github.com/miekg/dns/issues/577
	_, newError := NewRR(tkey.String())
	if newError != nil {
		t.Fatalf("unable to parse TKEY string: %s", newError)
	}
}

func TestShortMsg(t *testing.T) {
	testEmpty := []byte{}

	rr, _, err := UnpackRR(testEmpty, 0)
	if err == nil {
		t.Errorf("expected unpack failure for empty message, got %s", rr)
	}

	rr, _, err = UnpackRR(nil, 0)
	if err == nil {
		t.Errorf("expected unpack failure for nil message, got %s", rr)
	}

	rr = &MX{
		Hdr: RR_Header{
			Name:   mustParseName("miek.nl."),
			Rrtype: TypeMX,
			Class:  ClassINET,
			Ttl:    30,
		},
		Preference: 50,
	}

	msg := make([]byte, Len(rr))
	_, err = PackRR(rr, msg, 0, nil, false)
	if err != nil {
		t.Fatalf("unexpected error in TestShortMsg: %s", err)
		return
	}

	headerOff := Len(rr.Header())
	// manually set rdlength to 2, covering just the preference
	binary.BigEndian.PutUint16(msg[headerOff-2:headerOff], 2)

	rr, _, err = UnpackRR(msg, 0)
	if err == nil {
		t.Errorf("expected unpack success for short message, got %s", rr)
	}
}

var (
	sinkBool   bool
	sinkString string
)

func BenchmarkIsFQDN(b *testing.B) {
	b.Run("no_dot", func(b *testing.B) {
		var r bool
		for n := 0; n < b.N; n++ {
			r = IsFqdn("www.google.com")
		}
		sinkBool = r
	})
	b.Run("unescaped", func(b *testing.B) {
		var r bool
		for n := 0; n < b.N; n++ {
			r = IsFqdn("www.google.com.")
		}
		sinkBool = r
	})
	b.Run("escaped", func(b *testing.B) {
		var r bool
		for n := 0; n < b.N; n++ {
			r = IsFqdn(`www.google.com\\\\\\\\.`)
		}
		sinkBool = r
	})
}

func BenchmarkFQDN(b *testing.B) {
	b.Run("is_fqdn", func(b *testing.B) {
		var r string
		for n := 0; n < b.N; n++ {
			r = Fqdn("www.google.com.")
		}
		sinkString = r
	})
	b.Run("not_fqdn", func(b *testing.B) {
		var r string
		for n := 0; n < b.N; n++ {
			r = Fqdn("www.google.com")
		}
		sinkString = r
	})
}
