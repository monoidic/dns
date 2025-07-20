package dns

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const normal string = `
# Comment
domain somedomain.com
nameserver 10.28.10.2
nameserver 11.28.10.1
`

const missingNewline string = `
domain somedomain.com
nameserver 10.28.10.2
nameserver 11.28.10.1` // <- NOTE: NO newline.

func testConfig(t *testing.T, data string) {
	cc, err := ClientConfigFromReader(strings.NewReader(data))
	if err != nil {
		t.Fatalf("error parsing resolv.conf: %v", err)
	}
	if l := len(cc.Servers); l != 2 {
		t.Errorf("incorrect number of nameservers detected: %d", l)
	}
	if l := len(cc.Search); l != 1 {
		t.Errorf("domain directive not parsed correctly: %v", cc.Search)
	} else {
		if cc.Search[0].String() != "somedomain.com." {
			t.Errorf("domain is unexpected: %v", cc.Search[0])
		}
	}
}

func TestNameserver(t *testing.T)          { testConfig(t, normal) }
func TestMissingFinalNewLine(t *testing.T) { testConfig(t, missingNewline) }

func TestNdots(t *testing.T) {
	ndotsVariants := map[string]int{
		"options ndots:0":  0,
		"options ndots:1":  1,
		"options ndots:15": 15,
		"options ndots:16": 15,
		"options ndots:-1": 0,
		"":                 1,
	}

	for data := range ndotsVariants {
		cc, err := ClientConfigFromReader(strings.NewReader(data))
		if err != nil {
			t.Errorf("error parsing resolv.conf: %v", err)
		}
		if cc.Ndots != ndotsVariants[data] {
			t.Errorf("Ndots not properly parsed: (Expected: %d / Was: %d)", ndotsVariants[data], cc.Ndots)
		}
	}
}

func TestClientConfigFromReaderAttempts(t *testing.T) {
	testCases := []struct {
		data     string
		expected int
	}{
		{data: "options attempts:0", expected: 1},
		{data: "options attempts:1", expected: 1},
		{data: "options attempts:15", expected: 15},
		{data: "options attempts:16", expected: 16},
		{data: "options attempts:-1", expected: 1},
		{data: "options attempt:", expected: 2},
	}

	for _, test := range testCases {
		test := test
		t.Run(strings.Replace(test.data, ":", " ", -1), func(t *testing.T) {
			t.Parallel()

			cc, err := ClientConfigFromReader(strings.NewReader(test.data))
			if err != nil {
				t.Errorf("error parsing resolv.conf: %v", err)
			}
			if cc.Attempts != test.expected {
				t.Errorf("A attempts not properly parsed: (Expected: %d / Was: %d)", test.expected, cc.Attempts)
			}
		})
	}
}

func TestReadFromFile(t *testing.T) {
	tempDir := t.TempDir()

	path := filepath.Join(tempDir, "resolv.conf")
	if err := os.WriteFile(path, []byte(normal), 0o644); err != nil {
		t.Fatalf("writeFile: %v", err)
	}
	cc, err := ClientConfigFromFile(path)
	if err != nil {
		t.Fatalf("error parsing resolv.conf: %v", err)
	}
	if l := len(cc.Servers); l != 2 {
		t.Errorf("incorrect number of nameservers detected: %d", l)
	}
	if l := len(cc.Search); l != 1 {
		t.Errorf("domain directive not parsed correctly: %v", cc.Search)
	} else {
		if cc.Search[0].String() != "somedomain.com." {
			t.Errorf("domain is unexpected: %v", cc.Search[0])
		}
	}
}

func TestNameListNdots1(t *testing.T) {
	cfg := ClientConfig{
		Ndots: 1,
	}
	// fqdn should be only result returned
	names := cfg.NameList("miek.nl.")
	if len(names) != 1 {
		t.Errorf("NameList returned != 1 names: %v", names)
	} else if names[0].String() != "miek.nl." {
		t.Errorf("NameList didn't return sent fqdn domain: %v", names[0])
	}

	cfg.Search = []Name{mustParseName("test.")}
	// Sent domain has NDots and search
	names = cfg.NameList("miek.nl")
	expected := []Name{mustParseName("miek.nl."), mustParseName("miek.nl.test.")}
	if !slices.Equal(names, expected) {
		t.Errorf("Namelist returned %s, expected %s", names, expected)
	}
}

func TestNameListNdots2(t *testing.T) {
	cfg := ClientConfig{
		Ndots: 2,
	}

	// Sent domain has less than NDots and search
	cfg.Search = []Name{mustParseName("test.")}
	names := cfg.NameList("miek.nl")
	expected := []Name{mustParseName("miek.nl.test."), mustParseName("miek.nl.")}
	if !slices.Equal(names, expected) {
		t.Errorf("Namelist returned %s, expected %s", names, expected)
	}
}

func TestNameListNdots0(t *testing.T) {
	cfg := ClientConfig{
		Ndots: 0,
	}
	cfg.Search = []Name{mustParseName("test.")}
	// Sent domain has less than NDots and search
	names := cfg.NameList("miek")
	expected := []Name{mustParseName("miek."), mustParseName("miek.test.")}
	if !slices.Equal(names, expected) {
		t.Errorf("Namelist returned %s, expected %s", names, expected)
	}
}
