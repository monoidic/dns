package dns

import "testing"

func TestDotAsCatchAllWildcard(t *testing.T) {
	mux := NewServeMux()
	mux.Handle(mustParseName("."), HandlerFunc(HelloServer))
	mux.Handle(mustParseName("example.com."), HandlerFunc(AnotherHelloServer))

	handler := mux.match(mustParseName("www.miek.nl."), TypeTXT)
	if handler == nil {
		t.Error("wildcard match failed")
	}

	handler = mux.match(mustParseName("www.example.com."), TypeTXT)
	if handler == nil {
		t.Error("example.com match failed")
	}

	handler = mux.match(mustParseName("a.www.example.com."), TypeTXT)
	if handler == nil {
		t.Error("a.www.example.com match failed")
	}

	handler = mux.match(mustParseName("boe."), TypeTXT)
	if handler == nil {
		t.Error("boe. match failed")
	}
}

func TestCaseFolding(t *testing.T) {
	mux := NewServeMux()
	mux.Handle(mustParseName("_udp.example.com."), HandlerFunc(HelloServer))

	handler := mux.match(mustParseName("_dns._udp.example.com."), TypeSRV)
	if handler == nil {
		t.Error("case sensitive characters folded")
	}

	handler = mux.match(mustParseName("_DNS._UDP.EXAMPLE.COM."), TypeSRV)
	if handler == nil {
		t.Error("case insensitive characters not folded")
	}
}

func TestRootServer(t *testing.T) {
	mux := NewServeMux()
	mux.Handle(mustParseName("."), HandlerFunc(HelloServer))

	handler := mux.match(mustParseName("."), TypeNS)
	if handler == nil {
		t.Error("root match failed")
	}
}

func BenchmarkMuxMatch(b *testing.B) {
	mux := NewServeMux()
	mux.Handle(mustParseName("_udp.example.com."), HandlerFunc(HelloServer))

	bench := func(q string) func(*testing.B) {
		return func(b *testing.B) {
			for n := 0; n < b.N; n++ {
				handler := mux.match(mustParseName(q), TypeSRV)
				if handler == nil {
					b.Fatal("couldn't find match")
				}
			}
		}
	}
	b.Run("lowercase", bench("_dns._udp.example.com."))
	b.Run("uppercase", bench("_DNS._UDP.EXAMPLE.COM."))
}
