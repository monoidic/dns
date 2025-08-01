package dns

import (
	"errors"
	"io"
	"io/fs"
	"net/netip"
	"os"
	"strings"
	"testing"
	"testing/fstest"
)

func TestZoneParserGenerate(t *testing.T) {
	zone := "$ORIGIN example.org.\n$GENERATE 10-12 foo${2,3,d} IN A 127.0.0.$"

	wantRRs := []RR{
		&A{Hdr: RR_Header{Name: mustParseName("foo012.example.org.")}, A: netip.MustParseAddr("127.0.0.10")},
		&A{Hdr: RR_Header{Name: mustParseName("foo013.example.org.")}, A: netip.MustParseAddr("127.0.0.11")},
		&A{Hdr: RR_Header{Name: mustParseName("foo014.example.org.")}, A: netip.MustParseAddr("127.0.0.12")},
	}

	wantIdx := 0

	z := NewZoneParser(strings.NewReader(zone), Name{}, "")

	for rr, ok := z.Next(); ok; rr, ok = z.Next() {
		if wantIdx >= len(wantRRs) {
			t.Fatalf("expected %d RRs, but got more", len(wantRRs))
		}
		if got, want := rr.Header().Name, wantRRs[wantIdx].Header().Name; got != want {
			t.Fatalf("expected name %s, but got %s", want, got)
		}
		a, okA := rr.(*A)
		if !okA {
			t.Fatalf("expected *A RR, but got %T", rr)
		}
		if got, want := a.A, wantRRs[wantIdx].(*A).A; got != want {
			t.Fatalf("expected A with IP %v, but got %v", got, want)
		}
		wantIdx++
	}

	if err := z.Err(); err != nil {
		t.Fatalf("expected no error, but got %s", err)
	}

	if wantIdx != len(wantRRs) {
		t.Errorf("too few records, expected %d, got %d", len(wantRRs), wantIdx)
	}
}

func TestZoneParserInclude(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "dns")
	if err != nil {
		t.Fatalf("could not create tmpfile for test: %s", err)
	}
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.WriteString("foo\tIN\tA\t127.0.0.1"); err != nil {
		t.Fatalf("unable to write content to tmpfile %q: %s", tmpfile.Name(), err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatalf("could not close tmpfile %q: %s", tmpfile.Name(), err)
	}

	zone := "$ORIGIN example.org.\n$INCLUDE " + tmpfile.Name() + "\nbar\tIN\tA\t127.0.0.2"

	var got int
	z := NewZoneParser(strings.NewReader(zone), Name{}, "")
	z.SetIncludeAllowed(true)
	for rr, ok := z.Next(); ok; _, ok = z.Next() {
		switch rr.Header().Name {
		case mustParseName("foo.example.org."), mustParseName("bar.example.org."):
		default:
			t.Fatalf("expected foo.example.org. or bar.example.org., but got %s", rr.Header().Name)
		}
		got++
	}
	if err := z.Err(); err != nil {
		t.Fatalf("expected no error, but got %s", err)
	}

	if expected := 2; got != expected {
		t.Errorf("failed to parse zone after include, expected %d records, got %d", expected, got)
	}

	os.Remove(tmpfile.Name())

	z = NewZoneParser(strings.NewReader(zone), Name{}, "")
	z.SetIncludeAllowed(true)
	z.Next()
	if err := z.Err(); err == nil ||
		!strings.Contains(err.Error(), "failed to open") ||
		!strings.Contains(err.Error(), tmpfile.Name()) ||
		!strings.Contains(err.Error(), "no such file or directory") {
		t.Fatalf(`expected error to contain: "failed to open", %q and "no such file or directory" but got: %s`,
			tmpfile.Name(), err)
	}
}

func TestZoneParserIncludeFS(t *testing.T) {
	fsys := fstest.MapFS{
		"db.foo": &fstest.MapFile{
			Data: []byte("foo\tIN\tA\t127.0.0.1"),
		},
	}
	zone := "$ORIGIN example.org.\n$INCLUDE db.foo\nbar\tIN\tA\t127.0.0.2"

	var got int
	z := NewZoneParser(strings.NewReader(zone), Name{}, "")
	z.SetIncludeAllowed(true)
	z.SetIncludeFS(fsys)
	for rr, ok := z.Next(); ok; _, ok = z.Next() {
		switch rr.Header().Name {
		case mustParseName("foo.example.org."), mustParseName("bar.example.org."):
		default:
			t.Fatalf("expected foo.example.org. or bar.example.org., but got %s", rr.Header().Name)
		}
		got++
	}
	if err := z.Err(); err != nil {
		t.Fatalf("expected no error, but got %s", err)
	}

	if expected := 2; got != expected {
		t.Errorf("failed to parse zone after include, expected %d records, got %d", expected, got)
	}

	fsys = fstest.MapFS{}

	z = NewZoneParser(strings.NewReader(zone), Name{}, "")
	z.SetIncludeAllowed(true)
	z.SetIncludeFS(fsys)
	z.Next()
	if err := z.Err(); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf(`expected fs.ErrNotExist but got: %T %v`, err, err)
	}
}

func TestZoneParserIncludeFSPaths(t *testing.T) {
	fsys := fstest.MapFS{
		"baz/bat/db.foo": &fstest.MapFile{
			Data: []byte("foo\tIN\tA\t127.0.0.1"),
		},
	}

	for _, p := range []string{
		"../bat/db.foo",
		"/baz/bat/db.foo",
	} {
		zone := "$ORIGIN example.org.\n$INCLUDE " + p + "\nbar\tIN\tA\t127.0.0.2"
		var got int
		z := NewZoneParser(strings.NewReader(zone), Name{}, "baz/quux/db.bar")
		z.SetIncludeAllowed(true)
		z.SetIncludeFS(fsys)
		for rr, ok := z.Next(); ok; _, ok = z.Next() {
			switch rr.Header().Name {
			case mustParseName("foo.example.org."), mustParseName("bar.example.org."):
			default:
				t.Fatalf("$INCLUDE %q: expected foo.example.org. or bar.example.org., but got %s", p, rr.Header().Name)
			}
			got++
		}
		if err := z.Err(); err != nil {
			t.Fatalf("$INCLUDE %q: expected no error, but got %s", p, err)
		}
		if expected := 2; got != expected {
			t.Errorf("$INCLUDE %q: failed to parse zone after include, expected %d records, got %d", p, expected, got)
		}
	}
}

func TestZoneParserIncludeDisallowed(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "dns")
	if err != nil {
		t.Fatalf("could not create tmpfile for test: %s", err)
	}
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.WriteString("foo\tIN\tA\t127.0.0.1"); err != nil {
		t.Fatalf("unable to write content to tmpfile %q: %s", tmpfile.Name(), err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatalf("could not close tmpfile %q: %s", tmpfile.Name(), err)
	}

	zp := NewZoneParser(strings.NewReader("$INCLUDE "+tmpfile.Name()), mustParseName("example.org."), "")

	for _, ok := zp.Next(); ok; _, ok = zp.Next() {
	}

	const expect = "$INCLUDE directive not allowed"
	if err := zp.Err(); err == nil || !strings.Contains(err.Error(), expect) {
		t.Errorf("expected error to contain %q, got %v", expect, err)
	}
}

func TestZoneParserAddressAAAA(t *testing.T) {
	tests := []struct {
		record string
		want   *AAAA
	}{
		{
			record: "1.example.org. 600 IN AAAA ::1",
			want:   &AAAA{Hdr: RR_Header{Name: mustParseName("1.example.org.")}, AAAA: netip.IPv6Loopback()},
		},
		{
			record: "2.example.org. 600 IN AAAA ::FFFF:127.0.0.1",
			want:   &AAAA{Hdr: RR_Header{Name: mustParseName("2.example.org.")}, AAAA: netip.MustParseAddr("::FFFF:127.0.0.1")},
		},
	}

	for _, tc := range tests {
		got, err := NewRR(tc.record)
		if err != nil {
			t.Fatalf("expected no error, but got %s", err)
		}
		aaaa, ok := got.(*AAAA)
		if !ok {
			t.Fatalf("expected *AAAA RR, but got %T", got)
		}
		if aaaa.AAAA != tc.want.AAAA {
			t.Fatalf("expected AAAA with IP %v, but got %v", tc.want.AAAA, aaaa.AAAA)
		}
	}
}

func TestZoneParserTargetBad(t *testing.T) {
	records := []string{
		"bad.example.org. CNAME ; bad cname",
		"bad.example.org. HTTPS 10 ; bad https",
		"bad.example.org. MX 10 ; bad mx",
		"bad.example.org. SRV 1 0 80 ; bad srv",
	}

	for _, record := range records {
		const expect = "bad "
		if got, err := NewRR(record); err == nil || !strings.Contains(err.Error(), expect) {
			t.Errorf("NewRR(%v) = %v, want err to contain %q", record, got, expect)
		}
	}
}

func TestZoneParserAddressBad(t *testing.T) {
	records := []string{
		"1.bad.example.org. 600 IN A ::1",
		"2.bad.example.org. 600 IN A ::FFFF:127.0.0.1",
		"3.bad.example.org. 600 IN AAAA 127.0.0.1",
	}

	for _, record := range records {
		const expect = "bad A"
		if got, err := NewRR(record); err == nil || !strings.Contains(err.Error(), expect) {
			t.Errorf("NewRR(%v) = %v, want err to contain %q", record, got, expect)
		}
	}
}

func TestParseTA(t *testing.T) {
	rr, err := NewRR(` Ta 0 0 0`)
	if err != nil {
		t.Fatalf("expected no error, but got %s", err)
	}
	if rr == nil {
		t.Fatal(`expected a normal RR, but got nil`)
	}
}

var errTestReadError = &Error{"test error"}

type errReader struct{}

func (errReader) Read(p []byte) (int, error) { return 0, errTestReadError }

func TestParseZoneReadError(t *testing.T) {
	rr, err := ReadRR(errReader{}, "")
	if err == nil || !strings.Contains(err.Error(), errTestReadError.Error()) {
		t.Errorf("expected error to contain %q, but got %v", errTestReadError, err)
	}
	if rr != nil {
		t.Errorf("expected a nil RR, but got %v", rr)
	}
}

func TestUnexpectedNewline(t *testing.T) {
	zone := `
example.com. 60 PX
1000 TXT 1K
`
	zp := NewZoneParser(strings.NewReader(zone), mustParseName("example.com."), "")
	for _, ok := zp.Next(); ok; _, ok = zp.Next() {
	}

	const expect = `dns: unexpected newline: "\n" at line: 2:18`
	if err := zp.Err(); err == nil || err.Error() != expect {
		t.Errorf("expected error to contain %q, got %v", expect, err)
	}

	// Test that newlines inside braces still work.
	zone = `
example.com. 60 PX (
1000 TXT 1K )
`
	zp = NewZoneParser(strings.NewReader(zone), mustParseName("example.com."), "")

	var count int
	for _, ok := zp.Next(); ok; _, ok = zp.Next() {
		count++
	}

	if count != 1 {
		t.Errorf("expected 1 record, got %d", count)
	}

	if err := zp.Err(); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestParseRFC3597InvalidLength(t *testing.T) {
	// We need to space separate the 00s otherwise it will exceed the maximum token size
	// of the zone lexer.
	_, err := NewRR("example. 3600 CLASS1 TYPE1 \\# 65536 " + strings.Repeat("00 ", 65536))
	if err == nil {
		t.Error("should not have parsed excessively long RFC3579 record")
	}
}

func TestParseKnownRRAsRFC3597(t *testing.T) {
	t.Run("with RDATA", func(t *testing.T) {
		// This was found by oss-fuzz.
		_, err := NewRR("example. 3600 tYpe44 \\# 03 75  0100")
		if err != nil {
			t.Errorf("failed to parse RFC3579 format: %v", err)
		}

		rr, err := NewRR("example. 3600 CLASS1 TYPE1 \\# 4 7f000001")
		if err != nil {
			t.Fatalf("failed to parse RFC3579 format: %v", err)
		}

		if rr.Header().Rrtype != TypeA {
			t.Errorf("expected TypeA (1) Rrtype, but got %v", rr.Header().Rrtype)
		}

		a, ok := rr.(*A)
		if !ok {
			t.Fatalf("expected *A RR, but got %T", rr)
		}

		localhost := netip.AddrFrom4([4]byte{127, 0, 0, 1})
		if a.A != localhost {
			t.Errorf("expected A with IP %v, but got %v", localhost, a.A)
		}
	})
	t.Run("without RDATA", func(t *testing.T) {
		rr, err := NewRR("example. 3600 CLASS1 TYPE1 \\# 0")
		if err != nil {
			t.Fatalf("failed to parse RFC3579 format: %v", err)
		}

		if rr.Header().Rrtype != TypeA {
			t.Errorf("expected TypeA (1) Rrtype, but got %v", rr.Header().Rrtype)
		}

		a, ok := rr.(*A)
		if !ok {
			t.Fatalf("expected *A RR, but got %T", rr)
		}

		if a.A.IsValid() {
			t.Errorf("expected A with empty IP, but got %v", a.A)
		}
	})
}

func TestParseOpenEscape(t *testing.T) {
	if _, err := NewRR("example.net IN CNAME example.net."); err != nil {
		t.Fatalf("expected no error, but got: %s", err)
	}
	if _, err := NewRR(`example.net IN CNAME example.org\`); err == nil {
		t.Fatalf("expected an error, but got none")
	}
}

func BenchmarkNewRR(b *testing.B) {
	const name1 = "12345678901234567890123456789012345.12345678.123."
	const s = name1 + " 3600 IN MX 10 " + name1

	for n := 0; n < b.N; n++ {
		_, err := NewRR(s)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkReadRR(b *testing.B) {
	const name1 = "12345678901234567890123456789012345.12345678.123."
	const s = name1 + " 3600 IN MX 10 " + name1 + "\n"

	for n := 0; n < b.N; n++ {
		r := struct{ io.Reader }{strings.NewReader(s)}
		// r is now only an io.Reader and won't benefit from the
		// io.ByteReader special-case in zlexer.Next.

		_, err := ReadRR(r, "")
		if err != nil {
			b.Fatal(err)
		}
	}
}

const benchZone = `
foo. IN A 10.0.0.1 ; this is comment 1
foo. IN A (
	10.0.0.2 ; this is comment 2
)
; this is comment 3
foo. IN A 10.0.0.3
foo. IN A ( 10.0.0.4 ); this is comment 4

foo. IN A 10.0.0.5
; this is comment 5

foo. IN A 10.0.0.6

foo. IN DNSKEY 256 3 5 AwEAAb+8l ; this is comment 6
foo. IN NSEC miek.nl. TXT RRSIG NSEC; this is comment 7
foo. IN TXT "THIS IS TEXT MAN"; this is comment 8
`

func BenchmarkZoneParser(b *testing.B) {
	for n := 0; n < b.N; n++ {
		zp := NewZoneParser(strings.NewReader(benchZone), mustParseName("example.org."), "")

		for _, ok := zp.Next(); ok; _, ok = zp.Next() {
		}

		if err := zp.Err(); err != nil {
			b.Fatal(err)
		}
	}
}

func TestEscapedStringOffset(t *testing.T) {
	cases := []struct {
		input          string
		inputOffset    int
		expectedOffset int
		expectedOK     bool
	}{
		{"simple string with no escape sequences", 20, 20, true},
		{"simple string with no escape sequences", 500, -1, true},
		{`\;\088\\\;\120\\`, 0, 0, true},
		{`\;\088\\\;\120\\`, 1, 2, true},
		{`\;\088\\\;\120\\`, 2, 6, true},
		{`\;\088\\\;\120\\`, 3, 8, true},
		{`\;\088\\\;\120\\`, 4, 10, true},
		{`\;\088\\\;\120\\`, 5, 14, true},
		{`\;\088\\\;\120\\`, 6, 16, true},
		{`\;\088\\\;\120\\`, 7, -1, true},
		{`\`, 3, 0, false},
		{`a\`, 3, 0, false},
		{`aa\`, 3, 0, false},
		{`aaa\`, 3, 3, true},
		{`aaaa\`, 3, 3, true},
	}
	for i, test := range cases {
		outputOffset, outputOK := escapedStringOffset(test.input, test.inputOffset)
		if outputOffset != test.expectedOffset {
			t.Errorf(
				"Test %d (input %#q offset %d) returned offset %d but expected %d",
				i, test.input, test.inputOffset, outputOffset, test.expectedOffset,
			)
		}
		if outputOK != test.expectedOK {
			t.Errorf(
				"Test %d (input %#q offset %d) returned ok=%t but expected %t",
				i, test.input, test.inputOffset, outputOK, test.expectedOK,
			)
		}
	}
}
