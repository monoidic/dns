package dns

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

const maxPrintableLabel = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789x"

var (
	longDomain = maxPrintableLabel[:53] + strings.TrimSuffix(
		strings.Join([]string{".", ".", ".", ".", "."}, maxPrintableLabel[:49]), ".")

	reChar              = regexp.MustCompile(`.`)
	i                   = -1
	maxUnprintableLabel = reChar.ReplaceAllStringFunc(maxPrintableLabel, func(ch string) string {
		if i++; i >= 32 {
			i = 0
		}
		return fmt.Sprintf("\\%03d", i)
	})

	// These are the longest possible domain names in presentation format.
	longestDomain            = maxPrintableLabel[:61] + strings.Join([]string{".", ".", ".", "."}, maxPrintableLabel)
	longestUnprintableDomain = maxUnprintableLabel[:61*4] + strings.Join([]string{".", ".", ".", "."}, maxUnprintableLabel)
)

func TestPackNoSideEffect(t *testing.T) {
	m := new(Msg)
	name, _ := NameFromString("example.com.")
	m.SetQuestion(name, TypeNS)

	root, _ := NameFromString(".")
	a := new(Msg)
	o := &OPT{
		Hdr: RR_Header{
			Name:   root,
			Rrtype: TypeOPT,
		},
	}
	o.SetUDPSize(DefaultMsgSize)

	a.Extra = append(a.Extra, o)
	a.SetRcode(m, RcodeBadVers)

	a.Pack()
	if a.Rcode != RcodeBadVers {
		t.Errorf("after pack: Rcode is expected to be BADVERS")
	}
}

func TestPackExtendedBadCookie(t *testing.T) {
	m := new(Msg)
	name, _ := NameFromString("example.com.")
	m.SetQuestion(name, TypeNS)
	root, _ := NameFromString(".")

	a := new(Msg)
	a.SetReply(m)
	o := &OPT{
		Hdr: RR_Header{
			Name:   root,
			Rrtype: TypeOPT,
		},
	}
	o.SetUDPSize(DefaultMsgSize)
	a.Extra = append(a.Extra, o)

	a.SetRcode(m, RcodeBadCookie)

	edns0 := a.IsEdns0()
	if edns0 == nil {
		t.Fatal("Expected OPT RR")
	}
	// SetExtendedRcode is only called as part of `Pack()`, hence at this stage,
	// the OPT RR is not set yet.
	if edns0.ExtendedRcode() == RcodeBadCookie&0xFFFFFFF0 {
		t.Errorf("ExtendedRcode is expected to not be BADCOOKIE before Pack")
	}

	a.Pack()

	edns0 = a.IsEdns0()
	if edns0 == nil {
		t.Fatal("Expected OPT RR")
	}

	if edns0.ExtendedRcode() != RcodeBadCookie&0xFFFFFFF0 {
		t.Errorf("ExtendedRcode is expected to be BADCOOKIE after Pack")
	}
}

func TestUnPackExtendedRcode(t *testing.T) {
	m := new(Msg)
	name, _ := NameFromString("example.com.")
	m.SetQuestion(name, TypeNS)

	root, _ := NameFromString(".")
	a := new(Msg)
	a.SetReply(m)
	o := &OPT{
		Hdr: RR_Header{
			Name:   root,
			Rrtype: TypeOPT,
		},
	}
	o.SetUDPSize(DefaultMsgSize)
	a.Extra = append(a.Extra, o)

	a.SetRcode(m, RcodeBadCookie)

	packed, err := a.Pack()
	if err != nil {
		t.Fatalf("Could not unpack %v", a)
	}

	unpacked := new(Msg)
	if err := unpacked.Unpack(packed); err != nil {
		t.Fatalf("Failed to unpack message")
	}

	if unpacked.Rcode != RcodeBadCookie {
		t.Fatalf("Rcode should be matching RcodeBadCookie (%d), got (%d)", RcodeBadCookie, unpacked.Rcode)
	}
}

func TestUnpackDomainName(t *testing.T) {
	cases := []struct {
		label          string
		input          string
		expectedOutput string
		expectedError  string
	}{
		{
			"empty domain",
			"\x00",
			".",
			"",
		},
		{
			"long label",
			"?" + maxPrintableLabel + "\x00",
			maxPrintableLabel + ".",
			"",
		},
		{
			"unprintable label",
			"?" + regexp.MustCompile(`\\[0-9]+`).ReplaceAllStringFunc(maxUnprintableLabel,
				func(escape string) string {
					n, _ := strconv.ParseInt(escape[1:], 10, 8)
					return string(rune(n))
				}) + "\x00",
			maxUnprintableLabel + ".",
			"",
		},
		{
			"long domain",
			"5" + strings.Replace(longDomain, ".", "1", -1) + "\x00",
			longDomain + ".",
			"",
		},
		{
			"compression pointer",
			// an unrealistic but functional test referencing an offset _inside_ a label
			"\x03foo" + "\x05\x03com\x00" + "\x07example" + "\xC0\x05",
			"foo.\\003com\\000.example.com.",
			"",
		},
		{
			"too long domain",
			"6" + "x" + strings.Replace(longDomain, ".", "1", -1) + "\x00",
			"",
			ErrLongDomain.Error(),
		},
		{
			"too long by pointer",
			// a matryoshka doll name to get over 255 octets after expansion via internal pointers
			string([]byte{
				// 11 length values, first to last
				40, 37, 34, 31, 28, 25, 22, 19, 16, 13, 0,
				// 12 filler values
				120, 120, 120, 120, 120, 120, 120, 120, 120, 120, 120, 120,
				// 10 pointers, last to first
				192, 10, 192, 9, 192, 8, 192, 7, 192, 6, 192, 5, 192, 4, 192, 3, 192, 2, 192, 1,
			}),
			"",
			ErrLongDomain.Error(),
		},
		{
			"long by pointer",
			// a matryoshka doll name _not_ exceeding 255 octets after expansion
			string([]byte{
				// 11 length values, first to last
				37, 34, 31, 28, 25, 22, 19, 16, 13, 10, 0,
				// 9 filler values
				120, 120, 120, 120, 120, 120, 120, 120, 120,
				// 10 pointers, last to first
				192, 10, 192, 9, 192, 8, 192, 7, 192, 6, 192, 5, 192, 4, 192, 3, 192, 2, 192, 1,
			}),
			"" +
				(`\"\031\028\025\022\019\016\013\010\000xxxxxxxxx` +
					`\192\010\192\009\192\008\192\007\192\006\192\005\192\004\192\003\192\002.`) +
				(`\031\028\025\022\019\016\013\010\000xxxxxxxxx` +
					`\192\010\192\009\192\008\192\007\192\006\192\005\192\004\192\003.`) +
				(`\028\025\022\019\016\013\010\000xxxxxxxxx` +
					`\192\010\192\009\192\008\192\007\192\006\192\005\192\004.`) +
				(`\025\022\019\016\013\010\000xxxxxxxxx` +
					`\192\010\192\009\192\008\192\007\192\006\192\005.`) +
				`\022\019\016\013\010\000xxxxxxxxx\192\010\192\009\192\008\192\007\192\006.` +
				`\019\016\013\010\000xxxxxxxxx\192\010\192\009\192\008\192\007.` +
				`\016\013\010\000xxxxxxxxx\192\010\192\009\192\008.` +
				`\013\010\000xxxxxxxxx\192\010\192\009.` +
				`\010\000xxxxxxxxx\192\010.` +
				`\000xxxxxxxxx.`,
			"",
		},
		{"truncated name", "\x07example\x03", "", "dns: buffer size too small"},
		{"non-absolute name", "\x07example\x03com", "", "dns: buffer size too small"},
		{"compression pointer cycle (too many)", "\xC0\x00", "", "dns: too many compression pointers"},
		{
			"compression pointer cycle (too long)",
			"\x03foo" + "\x03bar" + "\x07example" + "\xC0\x04",
			"",
			ErrLongDomain.Error(),
		},
		{"forward compression pointer", "\x02\xC0\xFF\xC0\x01", "", ErrBuf.Error()},
		{"reserved compression pointer 0b10", "\x07example\x80", "", "dns: bad rdata"},
		{"reserved compression pointer 0b01", "\x07example\x40", "", "dns: bad rdata"},
	}
	for _, test := range cases {
		output, idx, err := UnpackDomainName([]byte(test.input), 0, true)
		expected := mustParseName(test.expectedOutput)
		if expected.String() != "" && output != expected {
			t.Errorf("%s: expected %s, got %s", test.label, test.expectedOutput, output)
		}
		if test.expectedError == "" && err != nil {
			t.Errorf("%s: expected no error, got %d %v", test.label, idx, err)
		} else if test.expectedError != "" && (err == nil || err.Error() != test.expectedError) {
			t.Errorf("%s: expected error %s, got %d %v", test.label, test.expectedError, idx, err)
		}
	}
}

func TestPackDomainNameCompressionMap(t *testing.T) {
	expected := map[Name]struct{}{
		mustParseName(`www\.this.is.\131an.example.org.`): {},
		mustParseName(`is.\131an.example.org.`):           {},
		mustParseName(`\131an.example.org.`):              {},
		mustParseName(`example.org.`):                     {},
		mustParseName(`org.`):                             {},
	}

	msg := make([]byte, 256)
	for _, compress := range []bool{true, false} {
		compression := make(map[Name]int)

		_, err := PackDomainName(mustParseName(`www\.this.is.\131an.example.org.`), msg, 0, compression, compress)
		if err != nil {
			t.Fatalf("PackDomainName failed: %v", err)
		}

		if !compressionMapsEqual(expected, compression) {
			t.Errorf("expected compression maps to be equal\n%s", compressionMapsDifference(expected, compression))
		}
	}
}

func TestPackDomainNameNSECTypeBitmap(t *testing.T) {
	ownername := mustParseName("some-very-long-ownername.com.")
	msg := &Msg{
		Compress: true,
		Answer: []RR{
			&NS{
				Hdr: RR_Header{
					Name:   ownername,
					Rrtype: TypeNS,
					Class:  ClassINET,
				},
				Ns: mustParseName("ns1.server.com."),
			},
			&NSEC{
				Hdr: RR_Header{
					Name:   ownername,
					Rrtype: TypeNSEC,
					Class:  ClassINET,
				},
				NextDomain: mustParseName("a.com."),
				TypeBitMap: TBMFromList([]Type{TypeNS, TypeNSEC}),
			},
		},
	}

	// Pack msg and then unpack into msg2
	buf, err := msg.Pack()
	if err != nil {
		t.Fatalf("msg.Pack failed: %v", err)
	}

	var msg2 Msg
	if err := msg2.Unpack(buf); err != nil {
		t.Fatalf("msg2.Unpack failed: %v", err)
	}

	if !IsDuplicate(msg.Answer[1], msg2.Answer[1]) {
		t.Error("message differs after packing and unpacking")

		// Print NSEC RR for both cases
		t.Logf("expected: %v", msg.Answer[1])
		t.Logf("got:      %v", msg2.Answer[1])
	}
}

func TestPackUnpackManyCompressionPointers(t *testing.T) {
	m := new(Msg)
	m.Compress = true
	name := mustParseName("example.org.")
	m.SetQuestion(name, TypeNS)

	for domain := "a."; len(domain) < maxDomainNameWireOctets; domain += "a." {
		m.Answer = append(m.Answer, &NS{Hdr: RR_Header{Name: mustParseName(domain), Rrtype: TypeNS, Class: ClassINET}, Ns: name})

		b, err := m.Pack()
		if err != nil {
			t.Fatalf("Pack failed for %q and %d records with: %v", domain, len(m.Answer), err)
		}

		var m2 Msg
		if err := m2.Unpack(b); err != nil {
			t.Fatalf("Unpack failed for %q and %d records with: %v", domain, len(m.Answer), err)
		}
	}
}

func TestLenDynamicA(t *testing.T) {
	for _, rr := range []RR{
		testRR("example.org. A"),
		testRR("example.org. AAAA"),
		testRR("example.org. L32"),
	} {
		msg := make([]byte, Len(rr))
		off, err := PackRR(rr, msg, 0, nil, false)
		if err != nil {
			t.Fatalf("PackRR failed for %T: %v", rr, err)
		}
		if off != len(msg) {
			t.Errorf("Len(rr) wrong for %T: Len(rr) = %d, PackRR(rr) = %d", rr, len(msg), off)
		}
	}
}
