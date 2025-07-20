package dns

import (
	"slices"
	"testing"
)

func TestCompareDomainName(t *testing.T) {
	s1 := mustParseName("www.miek.nl.")
	s2 := mustParseName("miek.nl.")
	s3 := mustParseName("www.bla.nl.")
	s4 := mustParseName("nl.www.bla.")
	s5 := mustParseName("nl.")
	s6 := mustParseName("miek.nl.")

	if CompareDomainName(s1, s2) != 2 {
		t.Errorf("%s with %s should be %d", s1, s2, 2)
	}
	if CompareDomainName(s1, s3) != 1 {
		t.Errorf("%s with %s should be %d", s1, s3, 1)
	}
	if CompareDomainName(s3, s4) != 0 {
		t.Errorf("%s with %s should be %d", s3, s4, 0)
	}
	// Non qualified tests
	if CompareDomainName(s1, s5) != 1 {
		t.Errorf("%s with %s should be %d", s1, s5, 1)
	}
	if CompareDomainName(s1, s6) != 2 {
		t.Errorf("%s with %s should be %d", s1, s5, 2)
	}

	if CompareDomainName(s1, mustParseName(".")) != 0 {
		t.Errorf("%s with %s should be %d", s1, s5, 0)
	}
	if CompareDomainName(mustParseName("."), mustParseName(".")) != 0 {
		t.Errorf("%s with %s should be %d", ".", ".", 0)
	}
	if CompareDomainName(mustParseName("test.com."), mustParseName("TEST.COM.")) != 2 {
		t.Errorf("test.com. and TEST.COM. should be an exact match")
	}
}

func TestSplit(t *testing.T) {
	splitter := map[string]int{
		"www.miek.nl.":    3,
		`www\.miek.nl.`:   2,
		`www\\.miek.nl.`:  3,
		`www\\\.miek.nl.`: 2,
		".":               0,
		"nl.":             1,
		"com.":            1,
	}
	for ss, i := range splitter {
		s := mustParseName(ss)
		if x := len(Split(s)); x != i {
			t.Errorf("labels should be %d, got %d: %s %v", i, x, s, Split(s))
		}
	}
}

func TestSplit2(t *testing.T) {
	splitter := map[string][]int{
		"www.miek.nl.": {0, 4, 9},
		"nl.":          {0},
	}
	for ss, i := range splitter {
		s := mustParseName(ss)
		x := Split(s)
		switch len(i) {
		case 1:
			if x[0] != i[0] {
				t.Errorf("labels should be %v, got %v: %s", i, x, s)
			}
		default:
			if x[0] != i[0] || x[1] != i[1] || x[2] != i[2] {
				t.Errorf("labels should be %v, got %v: %s", i, x, s)
			}
		}
	}
}

func TestNextLabel(t *testing.T) {
	type next struct {
		string
		int
	}
	nexts := map[next]int{
		{"", 1}:             0,
		{"www.miek.nl.", 0}: 4,
		{"www.miek.nl.", 4}: 9,
		{"www.miek.nl.", 9}: 12,
	}
	for s, i := range nexts {
		name := mustParseName(s.string)
		x, ok := NextLabel(name, s.int)
		if i != x {
			t.Errorf("label should be %d, got %d, %t: next %d, %s", i, x, ok, s.int, name)
		}
	}
}

func TestCountLabel(t *testing.T) {
	splitter := map[string]int{
		"www.miek.nl.": 3,
		"nl.":          1,
		".":            0,
	}
	for ss, i := range splitter {
		s := mustParseName(ss)
		x := s.CountLabel()
		if x != i {
			t.Errorf("CountLabel should have %d, got %d", i, x)
		}
	}
}

func TestSplitDomainName(t *testing.T) {
	labels := map[string][]string{
		"miek.nl.":       {"miek", "nl"},
		".":              nil,
		"www.miek.nl.":   {"www", "miek", "nl"},
		`www\.miek.nl.`:  {`www\.miek`, "nl"},
		`www\\.miek.nl.`: {`www\\`, "miek", "nl"},
	}
	for domainS, splits := range labels {
		domain := mustParseName(domainS)
		parts := domain.Split()
		if !slices.Equal(parts, splits) {
			t.Errorf("SplitDomainName returned %v for %s, expected %v", parts, domain, splits)
		}
	}
}

func TestIsDomainName(t *testing.T) {
	type ret struct {
		ok  bool
		lab int
	}
	names := map[string]*ret{
		".":                      {true, 1},
		"..":                     {false, 0},
		"double-dot..test.":      {false, 0},
		".leading-dot.test.":     {false, 0},
		"@.":                     {true, 1},
		"www.example.com.":       {true, 3},
		"www.e%ample.com.":       {true, 3},
		"mi\\k.nl.":              {true, 2},
		longestDomain:            {true, 4},
		longestUnprintableDomain: {true, 4},
	}
	for d, ok := range names {
		l, k := IsDomainName(d)
		if ok.ok != k || ok.lab != l {
			t.Errorf(" got %v %d for %s ", k, l, d)
			t.Errorf("have %v %d for %s ", ok.ok, ok.lab, d)
		}
	}
}

func TestIsFqdnEscaped(t *testing.T) {
	for s, expect := range map[string]bool{
		`.`:               true,
		`\.`:              false,
		`\\.`:             true,
		`\\\.`:            false,
		`\\\\.`:           true,
		`a.`:              true,
		`a\.`:             false,
		`a\\.`:            true,
		`a\\\.`:           false,
		`ab.`:             true,
		`ab\.`:            false,
		`ab\\.`:           true,
		`ab\\\.`:          false,
		`..`:              false,
		`.\.`:             false,
		`.\\.`:            false,
		`.\\\.`:           false,
		`example.org.`:    true,
		`example.org\.`:   false,
		`example.org\\.`:  true,
		`example.org\\\.`: false,
		`example\.org.`:   true,
		`example\\.org.`:  true,
		`example\\\.org.`: true,
		`\example.org.`:   true,
		`\\example.org.`:  true,
		`\\\example.org.`: true,
	} {
		if got := IsFqdn(s); got != expect {
			t.Errorf("IsFqdn(%q) = %t, expected %t", s, got, expect)
		}
	}
}

func TestCanonicalName(t *testing.T) {
	for s, expect := range map[string]string{
		"":                 ".",
		".":                ".",
		"tld.":             "tld.",
		"example.test.":    "example.test.",
		"Lower.CASE.test.": "lower.case.test.",
		"*.Test.":          "*.test.",
		"ÉxamplE.com.":     "Éxample.com.",
		"É.com.":           "É.com.",
	} {
		if got := CanonicalName(s); got != expect {
			t.Errorf("CanonicalName(%q) = %q, expected %q", s, got, expect)
		}
		if canonical := mustParseName(s).Canonical(); canonical != mustParseName(expect) {
			t.Errorf("Name.Canonical() for %s was %s, expected %s", s, canonical, expect)
		}
	}
}

func BenchmarkCompare(b *testing.B) {
	l := mustParseName("\\097.")
	r := mustParseName("A.")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		Compare(l, r)
	}
}

func TestCompare(t *testing.T) {
	domainsS := []string{ // based on an exanple from RFC 4034
		"example.",
		"a.example.",
		"yljkjljk.a.example.",
		"Z.a.example.",
		"zABC.a.EXAMPLE.",
		"a-.example.",
		"z.example.",
		"\001.z.example.",
		"*.z.example.",
		"\200.z.example.",
	}

	domains := make([]Name, len(domainsS))
	for i, v := range domainsS {
		domains[i] = mustParseName(v)
	}

	len_domains := len(domains)

	for i, domain := range domains {
		if i != 0 {
			prev_domain := domains[i-1]
			if !(Compare(prev_domain, domain) == -1 && Compare(domain, prev_domain) == 1) {
				t.Fatalf("prev comparison failure between %s and %s", prev_domain, domain)
			}
		}

		if Compare(domain, domain) != 0 {
			t.Fatalf("self comparison failure for %s", domain)
		}

		if i != len_domains-1 {
			next_domain := domains[i+1]
			if !(Compare(domain, next_domain) == -1 && Compare(next_domain, domain) == 1) {
				t.Fatalf("next comparison failure between %s and %s, %d and %d", domain, next_domain, Compare(domain, next_domain), Compare(next_domain, domain))
			}
		}
	}

	if Compare(mustParseName(`\097.`), mustParseName("A.")) != 0 {
		t.Fatal("failure to normalize DDD escape sequence")
	}
}

func BenchmarkSplitLabels(b *testing.B) {
	name := mustParseName("www.example.com.")
	for i := 0; i < b.N; i++ {
		Split(name)
	}
}

func BenchmarkLenLabels(b *testing.B) {
	name := mustParseName("www.example.com.")
	for i := 0; i < b.N; i++ {
		name.CountLabel()
	}
}

func BenchmarkCompareDomainName(b *testing.B) {
	lname := mustParseName("www.example.com.")
	rname := mustParseName("aa.example.com.")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		CompareDomainName(lname, rname)
	}
}

func BenchmarkIsSubDomain(b *testing.B) {
	www := mustParseName("www.example.com.")
	example := mustParseName("example.com.")
	aa := mustParseName("aa.example.com.")
	miek := mustParseName("miek.nl.")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		IsSubDomain(www, aa)
		IsSubDomain(example, aa)
		IsSubDomain(miek, aa)
	}
}

func BenchmarkNextLabelSimple(b *testing.B) {
	www := mustParseName("www.example.com")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		NextLabel(www, 0)
		NextLabel(www, 5)
		NextLabel(www, 12)
	}
}

func BenchmarkNextLabelComplex(b *testing.B) {
	www1 := mustParseName(`www\.example.com`)
	www2 := mustParseName(`www\\.example.com`)
	www3 := mustParseName(`www\\\.example.com`)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		NextLabel(www1, 0)
		NextLabel(www2, 0)
		NextLabel(www3, 0)
	}
}

func BenchmarkNextLabelMixed(b *testing.B) {
	d1 := mustParseName("www.example.com.")
	d2 := mustParseName(`www\.example.com.`)
	d3 := mustParseName(`www\\.example.com.`)
	d4 := mustParseName(`www\\\.example.com`)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		NextLabel(d1, 0)
		NextLabel(d2, 0)
		NextLabel(d1, 5)
		NextLabel(d3, 0)
		NextLabel(d1, 12)
		NextLabel(d4, 0)
	}
}
