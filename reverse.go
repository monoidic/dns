package dns

// StringToType is the reverse of TypeToString, needed for string parsing.
var StringToType = reverseMap(TypeToString)

// StringToClass is the reverse of ClassToString, needed for string parsing.
var StringToClass = reverseMap(ClassToString)

// StringToOpcode is a map of opcodes to strings.
var StringToOpcode = reverseMap(OpcodeToString)

// StringToRcode is a map of rcodes to strings.
var StringToRcode = reverseMap(RcodeToString)

func init() {
	// Preserve previous NOTIMP typo, see github.com/miekg/dns/issues/733.
	StringToRcode["NOTIMPL"] = RcodeNotImplemented
}

// StringToAlgorithm is the reverse of AlgorithmToString.
var StringToAlgorithm = reverseMap(AlgorithmToString)

// StringToHash is a map of names to hash IDs.
var StringToHash = reverseMap(HashToString)

// StringToCertType is the reverse of CertTypeToString.
var StringToCertType = reverseMap(CertTypeToString)

// StringToStatefulType is the reverse of StatefulTypeToString.
var StringToStatefulType = reverseMap(StatefulTypeToString)

// Reverse a map
func reverseMap[K, V comparable](m map[K]V) map[V]K {
	n := make(map[V]K, len(m))
	for k, v := range m {
		n[v] = k
	}
	return n
}
