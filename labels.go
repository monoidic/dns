package dns

import (
	"cmp"
	"slices"
	"strings"
)

// Holds a bunch of helper functions for dealing with labels.

// SplitDomainName splits a name string into it's labels.
// www.miek.nl. returns []string{"www", "miek", "nl"}
// .www.miek.nl. returns []string{"", "www", "miek", "nl"},
// The root label (.) returns nil. Note that using
// strings.Split(s) will work in most cases, but does not handle
// escaped dots (\.) for instance.
// s must be a syntactically valid domain name, see IsDomainName.
func (n Name) SplitRaw() []string {
	if n.String() == "" {
		return nil
	}
	var labels []string

	var off int
	for off+1 < len(n.encoded) {
		labelLen := int(n.encoded[off])
		off++
		labels = append(labels, n.encoded[off:off+labelLen])
		off += labelLen
	}
	return labels
}

func (n Name) Split() []string {
	labels := n.SplitRaw()
	ret := make([]string, len(labels))
	for i, v := range labels {
		ret[i] = escapeLabel([]byte(v))
	}
	return ret
}

// CompareDomainName compares the names s1 and s2 and
// returns how many labels they have in common starting from the *right*.
// The comparison stops at the first inequality. The names are downcased
// before the comparison.
//
// www.miek.nl. and miek.nl. have two labels in common: miek and nl
// www.miek.nl. and www.bla.nl. have one label in common: nl
//
// s1 and s2 must be syntactically valid domain names.
func CompareDomainName(s1, s2 Name) (n int) {
	// the first check: root label
	if s1.String() == "." || s2.String() == "." {
		return 0
	}

	s1Labels := s1.Split()
	s2Labels := s2.Split()
	slices.Reverse(s1Labels)
	slices.Reverse(s2Labels)
	for i := range min(len(s1Labels), len(s2Labels)) {
		if !equal(s1Labels[i], s2Labels[i]) {
			break
		}
		n++
	}
	return
}

// CountLabel counts the number of labels in the string s.
// s must be a syntactically valid domain name.
func (n Name) CountLabel() int {
	switch n.encoded {
	case "": // empty
		return 0
	}

	var off, labels int
	for {
		labelLen := int(n.encoded[off])
		off += labelLen + 1
		if off == len(n.encoded) {
			return labels
		}
		labels++
	}
}

// Split splits a name s into its label indexes.
// www.miek.nl. returns []int{0, 4, 9}, www.miek.nl also returns []int{0, 4, 9}.
// The root name (.) returns nil. Also see SplitDomainName.
// s must be a syntactically valid domain name.
func Split(s Name) []int {
	if s.encoded == "\x00" { // root
		return nil
	}
	idx := make([]int, 1, 3)
	off := 0
	end := false

	for {
		off, end = NextLabel(s, off)
		if end {
			return idx
		}
		idx = append(idx, off)
	}
}

// NextLabel returns the index of the start of the next label in the
// string s starting at offset.
// The bool end is true when the end of the string has been reached.
// Also see PrevLabel.
func NextLabel(s Name, offset int) (i int, end bool) {
	if s.encoded == "" {
		return 0, true
	}
	if offset >= len(s.encoded) {
		return s.EncodedLen(), true
	}
	labelLen := s.encoded[offset]
	i = offset + 1 + int(labelLen)
	if len(s.encoded) < i {
		return len(s.encoded), true
	}
	return i, i == len(s.encoded)-1
}

// Compare compares domains according to the canonical ordering specified in RFC4034
// returns an integer value similar to strcmp
// (0 for equal values, -1 if s1 < s2, 1 if s1 > s2)
func Compare(s1, s2 Name) int {
	s1Labels := s1.Canonical().SplitRaw()
	s2Labels := s2.Canonical().SplitRaw()

	slices.Reverse(s1Labels)
	slices.Reverse(s2Labels)

	for i := range min(len(s1Labels), len(s2Labels)) {
		s1l := s1Labels[i]
		s2l := s2Labels[i]
		if cmp := strings.Compare(s1l, s2l); cmp != 0 {
			return cmp
		}
	}

	return cmp.Compare(len(s1Labels), len(s2Labels))
}

// essentially strcasecmp
// (0 for equal values, -1 if s1 < s2, 1 if s1 > s2)
func labelCompare(a, b string) int {
	la := len(a)
	lb := len(b)
	for i := range min(la, lb) {
		ai := a[i]
		bi := b[i]
		if ai >= 'A' && ai <= 'Z' {
			ai |= 'a' - 'A'
		}
		if bi >= 'A' && bi <= 'Z' {
			bi |= 'a' - 'A'
		}
		if ai != bi {
			if ai > bi {
				return 1
			}
			return -1
		}
	}

	if la > lb {
		return 1
	}
	if la < lb {
		return -1
	}
	return 0
}

// equal compares a and b while ignoring case. It returns true when equal otherwise false.
func equal(a, b string) bool {
	// might be lifted into API function.
	if len(a) != len(b) {
		return false
	}

	return labelCompare(a, b) == 0
}
