package dns

import "testing"

func TestCompareDomainName(t *testing.T) {
	s1 := "www.miek.nl."
	s2 := "miek.nl."
	s3 := "www.bla.nl."
	s4 := "nl.www.bla."
	s5 := "nl."
	s6 := "miek.nl."

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

	if CompareDomainName(s1, ".") != 0 {
		t.Errorf("%s with %s should be %d", s1, s5, 0)
	}
	if CompareDomainName(".", ".") != 0 {
		t.Errorf("%s with %s should be %d", ".", ".", 0)
	}
	if CompareDomainName("test.com.", "TEST.COM.") != 2 {
		t.Errorf("test.com. and TEST.COM. should be an exact match")
	}
}

func TestSplit(t *testing.T) {
	splitter := map[string]int{
		"www.miek.nl.":    3,
		"www.miek.nl":     3,
		"www..miek.nl":    4,
		`www\.miek.nl.`:   2,
		`www\\.miek.nl.`:  3,
		`www\\\.miek.nl.`: 2,
		".":               0,
		"nl.":             1,
		"nl":              1,
		"com.":            1,
		".com.":           2,
	}
	for s, i := range splitter {
		if x := len(Split(s)); x != i {
			t.Errorf("labels should be %d, got %d: %s %v", i, x, s, Split(s))
		}
	}
}

func TestSplit2(t *testing.T) {
	splitter := map[string][]int{
		"www.miek.nl.": {0, 4, 9},
		"www.miek.nl":  {0, 4, 9},
		"nl":           {0},
	}
	for s, i := range splitter {
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
		x, ok := NextLabel(s.string, s.int)
		if i != x {
			t.Errorf("label should be %d, got %d, %t: next %d, %s", i, x, ok, s.int, s.string)
		}
	}
}

func TestPrevLabel(t *testing.T) {
	type prev struct {
		string
		int
	}
	prever := map[prev]int{
		{"", 1}:             0,
		{"www.miek.nl.", 0}: 12,
		{"www.miek.nl.", 1}: 9,
		{"www.miek.nl.", 2}: 4,

		{"www.miek.nl", 0}: 11,
		{"www.miek.nl", 1}: 9,
		{"www.miek.nl", 2}: 4,

		{"www.miek.nl.", 5}: 0,
		{"www.miek.nl", 5}:  0,

		{"www.miek.nl.", 3}: 0,
		{"www.miek.nl", 3}:  0,
	}
	for s, i := range prever {
		x, ok := PrevLabel(s.string, s.int)
		if i != x {
			t.Errorf("label should be %d, got %d, %t: previous %d, %s", i, x, ok, s.int, s.string)
		}
	}
}

func TestCountLabel(t *testing.T) {
	splitter := map[string]int{
		"www.miek.nl.": 3,
		"www.miek.nl":  3,
		"nl":           1,
		".":            0,
	}
	for s, i := range splitter {
		x := CountLabel(s)
		if x != i {
			t.Errorf("CountLabel should have %d, got %d", i, x)
		}
	}
}

func TestSplitDomainName(t *testing.T) {
	labels := map[string][]string{
		"miek.nl":       {"miek", "nl"},
		".":             nil,
		"www.miek.nl.":  {"www", "miek", "nl"},
		"www.miek.nl":   {"www", "miek", "nl"},
		"www..miek.nl":  {"www", "", "miek", "nl"},
		`www\.miek.nl`:  {`www\.miek`, "nl"},
		`www\\.miek.nl`: {`www\\`, "miek", "nl"},
		".www.miek.nl.": {"", "www", "miek", "nl"},
	}
domainLoop:
	for domain, splits := range labels {
		parts := SplitDomainName(domain)
		if len(parts) != len(splits) {
			t.Errorf("SplitDomainName returned %v for %s, expected %v", parts, domain, splits)
			continue domainLoop
		}
		for i := range parts {
			if parts[i] != splits[i] {
				t.Errorf("SplitDomainName returned %v for %s, expected %v", parts, domain, splits)
				continue domainLoop
			}
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
		"double-dot..test":       {false, 1},
		".leading-dot.test":      {false, 0},
		"@.":                     {true, 1},
		"www.example.com":        {true, 3},
		"www.e%ample.com":        {true, 3},
		"www.example.com.":       {true, 3},
		"mi\\k.nl.":              {true, 2},
		"mi\\k.nl":               {true, 2},
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
		".":                  true,
		"\\.":                false,
		"\\\\.":              true,
		"\\\\\\.":            false,
		"\\\\\\\\.":          true,
		"a.":                 true,
		"a\\.":               false,
		"a\\\\.":             true,
		"a\\\\\\.":           false,
		"ab.":                true,
		"ab\\.":              false,
		"ab\\\\.":            true,
		"ab\\\\\\.":          false,
		"..":                 true,
		".\\.":               false,
		".\\\\.":             true,
		".\\\\\\.":           false,
		"example.org.":       true,
		"example.org\\.":     false,
		"example.org\\\\.":   true,
		"example.org\\\\\\.": false,
		"example\\.org.":     true,
		"example\\\\.org.":   true,
		"example\\\\\\.org.": true,
		"\\example.org.":     true,
		"\\\\example.org.":   true,
		"\\\\\\example.org.": true,
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
		"tld":              "tld.",
		"tld.":             "tld.",
		"example.test":     "example.test.",
		"Lower.CASE.test.": "lower.case.test.",
		"*.Test":           "*.test.",
	} {
		if got := CanonicalName(s); got != expect {
			t.Errorf("CanonicalName(%q) = %q, expected %q", s, got, expect)
		}
	}
}

func BenchmarkSplitLabels(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Split("www.example.com.")
	}
}

func BenchmarkLenLabels(b *testing.B) {
	for i := 0; i < b.N; i++ {
		CountLabel("www.example.com.")
	}
}

func BenchmarkCompareDomainName(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		CompareDomainName("www.example.com.", "aa.example.com.")
	}
}

func BenchmarkIsSubDomain(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		IsSubDomain("www.example.com.", "aa.example.com.")
		IsSubDomain("example.com.", "aa.example.com.")
		IsSubDomain("miek.nl.", "aa.example.com.")
	}
}

func BenchmarkNextLabelSimple(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		NextLabel("www.example.com", 0)
		NextLabel("www.example.com", 5)
		NextLabel("www.example.com", 12)
	}
}

func BenchmarkPrevLabelSimple(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		PrevLabel("www.example.com", 0)
		PrevLabel("www.example.com", 5)
		PrevLabel("www.example.com", 12)
	}
}

func BenchmarkNextLabelComplex(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		NextLabel(`www\.example.com`, 0)
		NextLabel(`www\\.example.com`, 0)
		NextLabel(`www\\\.example.com`, 0)
	}
}

func BenchmarkPrevLabelComplex(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		PrevLabel(`www\.example.com`, 10)
		PrevLabel(`www\\.example.com`, 10)
		PrevLabel(`www\\\.example.com`, 10)
	}
}

func BenchmarkNextLabelMixed(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		NextLabel("www.example.com", 0)
		NextLabel(`www\.example.com`, 0)
		NextLabel("www.example.com", 5)
		NextLabel(`www\\.example.com`, 0)
		NextLabel("www.example.com", 12)
		NextLabel(`www\\\.example.com`, 0)
	}
}

func BenchmarkPrevLabelMixed(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		PrevLabel("www.example.com", 0)
		PrevLabel(`www\.example.com`, 10)
		PrevLabel("www.example.com", 5)
		PrevLabel(`www\\.example.com`, 10)
		PrevLabel("www.example.com", 12)
		PrevLabel(`www\\\.example.com`, 10)
	}
}

func BenchmarkCompare(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		Compare("\\097.", "A.")
	}
}

func TestCompare(t *testing.T) {
	domains := []string{ // based on an exanple from RFC 4034
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

	if Compare("\\097.", "A.") != 0 {
		t.Fatal("failure to normalize DDD escape sequence")
	}
}
