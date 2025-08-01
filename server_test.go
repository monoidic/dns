package dns

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sync/errgroup"
)

func HelloServer(w ResponseWriter, req *Msg) {
	m := new(Msg)
	m.SetReply(req)

	m.Extra = make([]RR, 1)
	m.Extra[0] = &TXT{Hdr: RR_Header{Name: m.Question[0].Name, Rrtype: TypeTXT, Class: ClassINET, Ttl: 0}, Txt: mustParseTxts("Hello world")}
	w.WriteMsg(m)
}

func HelloServerBadID(w ResponseWriter, req *Msg) {
	m := new(Msg)
	m.SetReply(req)
	m.Id++

	m.Extra = make([]RR, 1)
	m.Extra[0] = &TXT{Hdr: RR_Header{Name: m.Question[0].Name, Rrtype: TypeTXT, Class: ClassINET, Ttl: 0}, Txt: mustParseTxts("Hello world")}
	w.WriteMsg(m)
}

func HelloServerBadThenGoodID(w ResponseWriter, req *Msg) {
	m := new(Msg)
	m.SetReply(req)
	m.Id++

	m.Extra = make([]RR, 1)
	m.Extra[0] = &TXT{Hdr: RR_Header{Name: m.Question[0].Name, Rrtype: TypeTXT, Class: ClassINET, Ttl: 0}, Txt: mustParseTxts("Hello world")}
	w.WriteMsg(m)

	m.Id--
	w.WriteMsg(m)
}

func HelloServerEchoAddrPort(w ResponseWriter, req *Msg) {
	m := new(Msg)
	m.SetReply(req)

	remoteAddr := w.RemoteAddr().String()
	m.Extra = make([]RR, 1)
	m.Extra[0] = &TXT{Hdr: RR_Header{Name: m.Question[0].Name, Rrtype: TypeTXT, Class: ClassINET, Ttl: 0}, Txt: mustParseTxts(remoteAddr)}
	w.WriteMsg(m)
}

func AnotherHelloServer(w ResponseWriter, req *Msg) {
	m := new(Msg)
	m.SetReply(req)

	m.Extra = make([]RR, 1)
	m.Extra[0] = &TXT{Hdr: RR_Header{Name: m.Question[0].Name, Rrtype: TypeTXT, Class: ClassINET, Ttl: 0}, Txt: mustParseTxts("Hello example")}
	w.WriteMsg(m)
}

func RunLocalServer(pc net.PacketConn, l net.Listener, opts ...func(*Server)) (*Server, string, chan error, error) {
	server := &Server{
		PacketConn: pc,
		Listener:   l,

		ReadTimeout:  time.Hour,
		WriteTimeout: time.Hour,
	}

	waitLock := sync.Mutex{}
	waitLock.Lock()
	server.NotifyStartedFunc = waitLock.Unlock

	for _, opt := range opts {
		opt(server)
	}

	var (
		addr   string
		closer io.Closer
	)
	if l != nil {
		addr = l.Addr().String()
		closer = l
	} else {
		addr = pc.LocalAddr().String()
		closer = pc
	}

	// fin must be buffered so the goroutine below won't block
	// forever if fin is never read from. This always happens
	// if the channel is discarded and can happen in TestShutdownUDP.
	fin := make(chan error, 1)

	go func() {
		fin <- server.ActivateAndServe()
		closer.Close()
	}()

	waitLock.Lock()
	return server, addr, fin, nil
}

func RunLocalUDPServer(laddr string, opts ...func(*Server)) (*Server, string, chan error, error) {
	pc, err := net.ListenPacket("udp", laddr)
	if err != nil {
		return nil, "", nil, err
	}

	return RunLocalServer(pc, nil, opts...)
}

func RunLocalPacketConnServer(laddr string, opts ...func(*Server)) (*Server, string, chan error, error) {
	return RunLocalUDPServer(laddr, append(opts, func(srv *Server) {
		// Make srv.PacketConn opaque to trigger the generic code paths.
		srv.PacketConn = struct{ net.PacketConn }{srv.PacketConn}
	})...)
}

func RunLocalTCPServer(laddr string, opts ...func(*Server)) (*Server, string, chan error, error) {
	l, err := net.Listen("tcp", laddr)
	if err != nil {
		return nil, "", nil, err
	}

	return RunLocalServer(nil, l, opts...)
}

func RunLocalTLSServer(laddr string, config *tls.Config) (*Server, string, chan error, error) {
	return RunLocalTCPServer(laddr, func(srv *Server) {
		srv.Listener = tls.NewListener(srv.Listener, config)
	})
}

func RunLocalUnixServer(laddr string, opts ...func(*Server)) (*Server, string, chan error, error) {
	l, err := net.Listen("unix", laddr)
	if err != nil {
		return nil, "", nil, err
	}

	return RunLocalServer(nil, l, opts...)
}

func RunLocalUnixGramServer(laddr string, opts ...func(*Server)) (*Server, string, chan error, error) {
	pc, err := net.ListenPacket("unixgram", laddr)
	if err != nil {
		return nil, "", nil, err
	}

	return RunLocalServer(pc, nil, opts...)
}

func RunLocalUnixSeqPacketServer(laddr string) (chan interface{}, string, error) {
	pc, err := net.Listen("unixpacket", laddr)
	if err != nil {
		return nil, "", err
	}

	shutdownChan := make(chan interface{})
	go func() {
		pc.Accept()
		<-shutdownChan
	}()

	return shutdownChan, pc.Addr().String(), nil
}

func TestServing(t *testing.T) {
	for _, tc := range []struct {
		name      string
		network   string
		runServer func(laddr string, opts ...func(*Server)) (*Server, string, chan error, error)
	}{
		{"udp", "udp", RunLocalUDPServer},
		{"tcp", "tcp", RunLocalTCPServer},
		{"PacketConn", "udp", RunLocalPacketConnServer},
	} {
		t.Run(tc.name, func(t *testing.T) {
			HandleFunc(mustParseName("miek.nl."), HelloServer)
			HandleFunc(mustParseName("example.com."), AnotherHelloServer)
			defer HandleRemove(mustParseName("miek.nl."))
			defer HandleRemove(mustParseName("example.com."))

			s, addrstr, _, err := tc.runServer(":0")
			if err != nil {
				t.Fatalf("unable to run test server: %v", err)
			}
			defer s.Shutdown()

			c := &Client{
				Net: tc.network,
			}
			m := new(Msg)
			m.SetQuestion(mustParseName("miek.nl."), TypeTXT)
			r, _, err := c.Exchange(m, addrstr)
			if err != nil || len(r.Extra) == 0 {
				t.Fatal("failed to exchange miek.nl", err)
			}
			txt := r.Extra[0].(*TXT).Txt.SplitStr()[0]
			if txt != "Hello world" {
				t.Error("unexpected result for miek.nl", txt, "!= Hello world")
			}

			m.SetQuestion(mustParseName("example.com."), TypeTXT)
			r, _, err = c.Exchange(m, addrstr)
			if err != nil {
				t.Fatal("failed to exchange example.com", err)
			}
			txt = r.Extra[0].(*TXT).Txt.SplitStr()[0]
			if txt != "Hello example" {
				t.Error("unexpected result for example.com", txt, "!= Hello example")
			}

			// Test Mixes cased as noticed by Ask.
			m.SetQuestion(mustParseName("eXaMplE.cOm."), TypeTXT)
			r, _, err = c.Exchange(m, addrstr)
			if err != nil {
				t.Error("failed to exchange eXaMplE.cOm", err)
			}
			if len(r.Extra) == 0 {
				t.Fatalf("no txt record in %s", r)
			}
			txtRR := r.Extra[0].(*TXT)
			if len(txtRR.Txt.Split()) == 0 {
				t.Fatalf("no txt data in %s", txtRR)
			}
			txt = txtRR.Txt.SplitStr()[0]
			if txt != "Hello example" {
				t.Error("unexpected result for example.com", txt, "!= Hello example")
			}
		})
	}
}

// Verify that the server responds to a query with Z flag on, ignoring the flag, and does not echoes it back
func TestServeIgnoresZFlag(t *testing.T) {
	HandleFunc(mustParseName("example.com."), AnotherHelloServer)

	s, addrstr, _, err := RunLocalUDPServer(":0")
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer s.Shutdown()

	c := new(Client)
	m := new(Msg)

	// Test the Z flag is not echoed
	m.SetQuestion(mustParseName("example.com."), TypeTXT)
	m.Zero = true
	r, _, err := c.Exchange(m, addrstr)
	if err != nil {
		t.Fatal("failed to exchange example.com with +zflag", err)
	}
	if r.Zero {
		t.Error("the response should not have Z flag set - even for a query which does")
	}
	if r.Rcode != RcodeSuccess {
		t.Errorf("expected rcode %v, got %v", RcodeSuccess, r.Rcode)
	}
}

// Verify that the server responds to a query with unsupported Opcode with a NotImplemented error and that Opcode is unchanged.
func TestServeNotImplemented(t *testing.T) {
	HandleFunc(mustParseName("example.com."), AnotherHelloServer)
	opcode := 15

	s, addrstr, _, err := RunLocalUDPServer(":0")
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer s.Shutdown()

	c := new(Client)
	m := new(Msg)

	// Test that Opcode is like the unchanged from request Opcode and that Rcode is set to NotImplemented
	m.SetQuestion(mustParseName("example.com."), TypeTXT)
	m.Opcode = opcode
	r, _, err := c.Exchange(m, addrstr)
	if err != nil {
		t.Fatal("failed to exchange example.com with +zflag", err)
	}
	if r.Opcode != opcode {
		t.Errorf("expected opcode %v, got %v", opcode, r.Opcode)
	}
	if r.Rcode != RcodeNotImplemented {
		t.Errorf("expected rcode %v, got %v", RcodeNotImplemented, r.Rcode)
	}
}

func TestServingTLS(t *testing.T) {
	HandleFunc(mustParseName("miek.nl."), HelloServer)
	HandleFunc(mustParseName("example.com."), AnotherHelloServer)
	defer HandleRemove(mustParseName("miek.nl."))
	defer HandleRemove(mustParseName("example.com."))

	cert, err := tls.X509KeyPair(CertPEMBlock, KeyPEMBlock)
	if err != nil {
		t.Fatalf("unable to build certificate: %v", err)
	}

	config := tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	s, addrstr, _, err := RunLocalTLSServer(":0", &config)
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer s.Shutdown()

	c := new(Client)
	c.Net = "tcp-tls"
	c.TLSConfig = &tls.Config{
		InsecureSkipVerify: true,
	}

	m := new(Msg)
	m.SetQuestion(mustParseName("miek.nl."), TypeTXT)
	r, _, err := c.Exchange(m, addrstr)
	if err != nil || len(r.Extra) == 0 {
		t.Fatal("failed to exchange miek.nl", err)
	}
	txt := r.Extra[0].(*TXT).Txt.SplitStr()[0]
	if txt != "Hello world" {
		t.Error("unexpected result for miek.nl", txt, "!= Hello world")
	}

	m.SetQuestion(mustParseName("example.com."), TypeTXT)
	r, _, err = c.Exchange(m, addrstr)
	if err != nil {
		t.Fatal("failed to exchange example.com", err)
	}
	txt = r.Extra[0].(*TXT).Txt.SplitStr()[0]
	if txt != "Hello example" {
		t.Error("unexpected result for example.com", txt, "!= Hello example")
	}

	// Test Mixes cased as noticed by Ask.
	m.SetQuestion(mustParseName("eXaMplE.cOm."), TypeTXT)
	r, _, err = c.Exchange(m, addrstr)
	if err != nil {
		t.Error("failed to exchange eXaMplE.cOm", err)
	}
	if len(r.Extra) == 0 {
		t.Fatalf("no txt in %s", r)
	}
	txtRR := r.Extra[0].(*TXT)
	if len(txtRR.Txt.Split()) == 0 {
		t.Fatalf("no data in txt RR %s", txtRR)
	}
	txt = txtRR.Txt.SplitStr()[0]
	if txt != "Hello example" {
		t.Error("unexpected result for example.com", txt, "!= Hello example")
	}
}

// TestServingTLSConnectionState tests that we only can access
// tls.ConnectionState under a DNS query handled by a TLS DNS server.
// This test will sequentially create a TLS, UDP and TCP server, attach a custom
// handler which will set a testing error if tls.ConnectionState is available
// when it is not expected, or the other way around.
func TestServingTLSConnectionState(t *testing.T) {
	handlerResponse := "Hello example"
	// tlsHandlerTLS is a HandlerFunc that can be set to expect or not TLS
	// connection state.
	tlsHandlerTLS := func(tlsExpected bool) func(ResponseWriter, *Msg) {
		return func(w ResponseWriter, req *Msg) {
			m := new(Msg)
			m.SetReply(req)
			tlsFound := true
			if connState := w.(ConnectionStater).ConnectionState(); connState == nil {
				tlsFound = false
			}
			if tlsFound != tlsExpected {
				t.Errorf("TLS connection state available: %t, expected: %t", tlsFound, tlsExpected)
			}
			m.Extra = make([]RR, 1)
			m.Extra[0] = &TXT{Hdr: RR_Header{Name: m.Question[0].Name, Rrtype: TypeTXT, Class: ClassINET, Ttl: 0}, Txt: mustParseTxts(handlerResponse)}
			w.WriteMsg(m)
		}
	}

	// Question used in tests
	m := new(Msg)
	m.SetQuestion(mustParseName("tlsstate.example.net."), TypeTXT)

	// TLS DNS server
	HandleFunc(mustParseName("."), tlsHandlerTLS(true))
	cert, err := tls.X509KeyPair(CertPEMBlock, KeyPEMBlock)
	if err != nil {
		t.Fatalf("unable to build certificate: %v", err)
	}

	config := tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	s, addrstr, _, err := RunLocalTLSServer(":0", &config)
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer s.Shutdown()

	// TLS DNS query
	c := &Client{
		Net: "tcp-tls",
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	_, _, err = c.Exchange(m, addrstr)
	if err != nil {
		t.Error("failed to exchange tlsstate.example.net", err)
	}

	HandleRemove(mustParseName("."))
	// UDP DNS Server
	HandleFunc(mustParseName("."), tlsHandlerTLS(false))
	defer HandleRemove(mustParseName("."))
	s, addrstr, _, err = RunLocalUDPServer(":0")
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer s.Shutdown()

	// UDP DNS query
	c = new(Client)
	_, _, err = c.Exchange(m, addrstr)
	if err != nil {
		t.Error("failed to exchange tlsstate.example.net", err)
	}

	// TCP DNS Server
	s, addrstr, _, err = RunLocalTCPServer(":0")
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer s.Shutdown()

	// TCP DNS query
	c = &Client{Net: "tcp"}
	_, _, err = c.Exchange(m, addrstr)
	if err != nil {
		t.Error("failed to exchange tlsstate.example.net", err)
	}
}

func TestServingListenAndServe(t *testing.T) {
	HandleFunc(mustParseName("example.com."), AnotherHelloServer)
	defer HandleRemove(mustParseName("example.com."))

	waitLock := sync.Mutex{}
	server := &Server{Addr: ":0", Net: "udp", ReadTimeout: time.Hour, WriteTimeout: time.Hour, NotifyStartedFunc: waitLock.Unlock}
	waitLock.Lock()

	go func() {
		server.ListenAndServe()
	}()
	waitLock.Lock()

	c, m := new(Client), new(Msg)
	m.SetQuestion(mustParseName("example.com."), TypeTXT)
	addr := server.PacketConn.LocalAddr().String() // Get address via the PacketConn that gets set.
	r, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatal("failed to exchange example.com", err)
	}
	txt := r.Extra[0].(*TXT).Txt.SplitStr()[0]
	if txt != "Hello example" {
		t.Error("unexpected result for example.com", txt, "!= Hello example")
	}
	server.Shutdown()
}

func TestServingListenAndServeTLS(t *testing.T) {
	HandleFunc(mustParseName("example.com."), AnotherHelloServer)
	defer HandleRemove(mustParseName("example.com."))

	cert, err := tls.X509KeyPair(CertPEMBlock, KeyPEMBlock)
	if err != nil {
		t.Fatalf("unable to build certificate: %v", err)
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	waitLock := sync.Mutex{}
	server := &Server{Addr: ":0", Net: "tcp", TLSConfig: config, ReadTimeout: time.Hour, WriteTimeout: time.Hour, NotifyStartedFunc: waitLock.Unlock}
	waitLock.Lock()

	go func() {
		server.ListenAndServe()
	}()
	waitLock.Lock()

	c, m := new(Client), new(Msg)
	c.Net = "tcp"
	m.SetQuestion(mustParseName("example.com."), TypeTXT)
	addr := server.Listener.Addr().String() // Get address via the Listener that gets set.
	r, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatal(err)
	}
	txt := r.Extra[0].(*TXT).Txt.SplitStr()[0]
	if txt != "Hello example" {
		t.Error("unexpected result for example.com", txt, "!= Hello example")
	}
	server.Shutdown()
}

func BenchmarkServe(b *testing.B) {
	b.StopTimer()
	HandleFunc(mustParseName("miek.nl."), HelloServer)
	defer HandleRemove(mustParseName("miek.nl."))
	a := runtime.GOMAXPROCS(4)

	s, addrstr, _, err := RunLocalUDPServer(":0")
	if err != nil {
		b.Fatalf("unable to run test server: %v", err)
	}
	defer s.Shutdown()

	c := new(Client)
	m := new(Msg)
	m.SetQuestion(mustParseName("miek.nl."), TypeSOA)

	b.StartTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := c.Exchange(m, addrstr)
		if err != nil {
			b.Fatalf("Exchange failed: %v", err)
		}
	}
	runtime.GOMAXPROCS(a)
}

func BenchmarkServe6(b *testing.B) {
	b.StopTimer()
	HandleFunc(mustParseName("miek.nl."), HelloServer)
	defer HandleRemove(mustParseName("miek.nl."))
	a := runtime.GOMAXPROCS(4)
	s, addrstr, _, err := RunLocalUDPServer("[::1]:0")
	if err != nil {
		if strings.Contains(err.Error(), "bind: cannot assign requested address") {
			b.Skip("missing IPv6 support")
		}
		b.Fatalf("unable to run test server: %v", err)
	}
	defer s.Shutdown()

	c := new(Client)
	m := new(Msg)
	m.SetQuestion(mustParseName("miek.nl."), TypeSOA)

	b.StartTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := c.Exchange(m, addrstr)
		if err != nil {
			b.Fatalf("Exchange failed: %v", err)
		}
	}
	runtime.GOMAXPROCS(a)
}

func HelloServerCompress(w ResponseWriter, req *Msg) {
	m := new(Msg)
	m.SetReply(req)
	m.Extra = make([]RR, 1)
	m.Extra[0] = &TXT{Hdr: RR_Header{Name: m.Question[0].Name, Rrtype: TypeTXT, Class: ClassINET, Ttl: 0}, Txt: mustParseTxts("Hello world")}
	m.Compress = true
	w.WriteMsg(m)
}

func BenchmarkServeCompress(b *testing.B) {
	b.StopTimer()
	HandleFunc(mustParseName("miek.nl."), HelloServerCompress)
	defer HandleRemove(mustParseName("miek.nl."))
	a := runtime.GOMAXPROCS(4)
	s, addrstr, _, err := RunLocalUDPServer(":0")
	if err != nil {
		b.Fatalf("unable to run test server: %v", err)
	}
	defer s.Shutdown()

	c := new(Client)
	m := new(Msg)
	m.SetQuestion(mustParseName("miek.nl."), TypeSOA)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := c.Exchange(m, addrstr)
		if err != nil {
			b.Fatalf("Exchange failed: %v", err)
		}
	}
	runtime.GOMAXPROCS(a)
}

type maxRec struct {
	max int
	sync.RWMutex
}

var M = new(maxRec)

func HelloServerLargeResponse(resp ResponseWriter, req *Msg) {
	m := new(Msg)
	m.SetReply(req)
	m.Authoritative = true
	m1 := 0
	M.RLock()
	m1 = M.max
	M.RUnlock()
	for i := range m1 {
		aRec := &A{
			Hdr: RR_Header{
				Name:   req.Question[0].Name,
				Rrtype: TypeA,
				Class:  ClassINET,
				Ttl:    0,
			},
			A: netip.MustParseAddr(fmt.Sprintf("127.0.0.%d", i+1)),
		}
		m.Answer = append(m.Answer, aRec)
	}
	resp.WriteMsg(m)
}

func TestServingLargeResponses(t *testing.T) {
	HandleFunc(mustParseName("example."), HelloServerLargeResponse)
	defer HandleRemove(mustParseName("example."))

	s, addrstr, _, err := RunLocalUDPServer(":0")
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer s.Shutdown()

	// Create request
	m := new(Msg)
	m.SetQuestion(mustParseName("web.service.example."), TypeANY)

	c := new(Client)
	c.Net = "udp"
	M.Lock()
	M.max = 2
	M.Unlock()
	_, _, err = c.Exchange(m, addrstr)
	if err != nil {
		t.Errorf("failed to exchange: %v", err)
	}
	// This must fail
	M.Lock()
	M.max = 20
	M.Unlock()
	_, _, err = c.Exchange(m, addrstr)
	if err == nil {
		t.Error("failed to fail exchange, this should generate packet error")
	}
	// But this must work again
	c.UDPSize = 7000
	_, _, err = c.Exchange(m, addrstr)
	if err != nil {
		t.Errorf("failed to exchange: %v", err)
	}
}

func TestServingResponse(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode.")
	}
	HandleFunc(mustParseName("miek.nl."), HelloServer)
	s, addrstr, _, err := RunLocalUDPServer(":0")
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer s.Shutdown()

	c := new(Client)
	m := new(Msg)
	m.SetQuestion(mustParseName("miek.nl."), TypeTXT)
	m.Response = false
	_, _, err = c.Exchange(m, addrstr)
	if err != nil {
		t.Fatal("failed to exchange", err)
	}
	m.Response = true // this holds up the reply, set short read time out to avoid waiting too long
	c.ReadTimeout = 100 * time.Millisecond
	_, _, err = c.Exchange(m, addrstr)
	if err == nil {
		t.Fatal("exchanged response message")
	}
}

func TestShutdownTCP(t *testing.T) {
	s, _, fin, err := RunLocalTCPServer(":0")
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	err = s.Shutdown()
	if err != nil {
		t.Fatalf("could not shutdown test TCP server, %v", err)
	}
	select {
	case err := <-fin:
		if err != nil {
			t.Errorf("error returned from ActivateAndServe, %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("could not shutdown test TCP server. Gave up waiting")
	}
}

func init() {
	testShutdownNotify = &sync.Cond{
		L: new(sync.Mutex),
	}
}

func checkInProgressQueriesAtShutdownServer(t *testing.T, srv *Server, addr string, client *Client) {
	const requests = 15 // enough to make this interesting? TODO: find a proper value

	var errOnce sync.Once
	// t.Fail will panic if it's called after the test function has
	// finished. Burning the sync.Once with a defer will prevent the
	// handler from calling t.Errorf after we've returned.
	defer errOnce.Do(func() {})

	toHandle := int32(requests)
	HandleFunc(mustParseName("example.com."), func(w ResponseWriter, req *Msg) {
		defer atomic.AddInt32(&toHandle, -1)

		// Wait until ShutdownContext is called before replying.
		testShutdownNotify.L.Lock()
		testShutdownNotify.Wait()
		testShutdownNotify.L.Unlock()

		m := new(Msg)
		m.SetReply(req)
		m.Extra = make([]RR, 1)
		m.Extra[0] = &TXT{Hdr: RR_Header{Name: m.Question[0].Name, Rrtype: TypeTXT, Class: ClassINET, Ttl: 0}, Txt: mustParseTxts("Hello world")}

		if err := w.WriteMsg(m); err != nil {
			errOnce.Do(func() {
				t.Errorf("ResponseWriter.WriteMsg error: %s", err)
			})
		}
	})
	defer HandleRemove(mustParseName("example.com."))

	client.Timeout = 1 * time.Second

	conns := make([]*Conn, requests)
	eg := new(errgroup.Group)

	for i := range conns {
		conn := &conns[i]
		eg.Go(func() error {
			var err error
			*conn, err = client.Dial(addr)
			return err
		})
	}

	if eg.Wait() != nil {
		t.Fatalf("client.Dial error: %v", eg.Wait())
	}

	m := new(Msg)
	m.SetQuestion(mustParseName("example.com."), TypeTXT)
	eg = new(errgroup.Group)

	for _, conn := range conns {
		conn := conn
		eg.Go(func() error {
			conn.SetWriteDeadline(time.Now().Add(client.Timeout))

			return conn.WriteMsg(m)
		})
	}

	if eg.Wait() != nil {
		t.Fatalf("conn.WriteMsg error: %v", eg.Wait())
	}

	// This sleep is needed to allow time for the requests to
	// pass from the client through the kernel and back into
	// the server. Without it, some requests may still be in
	// the kernel's buffer when ShutdownContext is called.
	time.Sleep(100 * time.Millisecond)

	eg = new(errgroup.Group)

	for _, conn := range conns {
		conn := conn
		eg.Go(func() error {
			conn.SetReadDeadline(time.Now().Add(client.Timeout))

			_, err := conn.ReadMsg()
			return err
		})
	}

	ctx, cancel := context.WithTimeout(context.Background(), client.Timeout)
	defer cancel()

	if err := srv.ShutdownContext(ctx); err != nil {
		t.Errorf("could not shutdown test server: %v", err)
	}

	if left := atomic.LoadInt32(&toHandle); left != 0 {
		t.Errorf("ShutdownContext returned before %d replies", left)
	}

	if eg.Wait() != nil {
		t.Errorf("conn.ReadMsg error: %v", eg.Wait())
	}

	srv.lock.RLock()
	defer srv.lock.RUnlock()
	if len(srv.conns) != 0 {
		t.Errorf("TCP connection tracking map not empty after ShutdownContext; map still contains %d connections", len(srv.conns))
	}
}

func TestInProgressQueriesAtShutdownTCP(t *testing.T) {
	s, addr, _, err := RunLocalTCPServer(":0")
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}

	c := &Client{Net: "tcp"}
	checkInProgressQueriesAtShutdownServer(t, s, addr, c)
}

func TestShutdownTLS(t *testing.T) {
	cert, err := tls.X509KeyPair(CertPEMBlock, KeyPEMBlock)
	if err != nil {
		t.Fatalf("unable to build certificate: %v", err)
	}

	config := tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	s, _, _, err := RunLocalTLSServer(":0", &config)
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	err = s.Shutdown()
	if err != nil {
		t.Errorf("could not shutdown test TLS server, %v", err)
	}
}

func TestInProgressQueriesAtShutdownTLS(t *testing.T) {
	cert, err := tls.X509KeyPair(CertPEMBlock, KeyPEMBlock)
	if err != nil {
		t.Fatalf("unable to build certificate: %v", err)
	}

	config := tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	s, addr, _, err := RunLocalTLSServer(":0", &config)
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}

	c := &Client{
		Net: "tcp-tls",
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	checkInProgressQueriesAtShutdownServer(t, s, addr, c)
}

func TestHandlerCloseTCP(t *testing.T) {
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		panic(err)
	}
	addr := ln.Addr().String()

	server := &Server{Addr: addr, Net: "tcp", Listener: ln}

	hname := mustParseName("testhandlerclosetcp.")
	triggered := make(chan struct{})
	HandleFunc(hname, func(w ResponseWriter, r *Msg) {
		close(triggered)
		w.Close()
	})
	defer HandleRemove(hname)

	go func() {
		defer server.Shutdown()
		c := &Client{Net: "tcp"}
		m := new(Msg).SetQuestion(hname, 1)
		tries := 0
	exchange:
		_, _, err := c.Exchange(m, addr)
		if err != nil && err != io.EOF {
			t.Errorf("exchange failed: %v", err)
			if tries == 3 {
				return
			}
			time.Sleep(time.Second / 10)
			tries++
			goto exchange
		}
	}()
	if err := server.ActivateAndServe(); err != nil {
		t.Fatalf("ActivateAndServe failed: %v", err)
	}
	select {
	case <-triggered:
	default:
		t.Fatalf("handler never called")
	}
}

func TestShutdownUDP(t *testing.T) {
	s, _, fin, err := RunLocalUDPServer(":0")
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	err = s.Shutdown()
	if err != nil {
		t.Errorf("could not shutdown test UDP server, %v", err)
	}
	select {
	case err := <-fin:
		if err != nil {
			t.Errorf("error returned from ActivateAndServe, %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("could not shutdown test UDP server. Gave up waiting")
	}
}

func TestShutdownPacketConn(t *testing.T) {
	s, _, fin, err := RunLocalPacketConnServer(":0")
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	err = s.Shutdown()
	if err != nil {
		t.Errorf("could not shutdown test UDP server, %v", err)
	}
	select {
	case err := <-fin:
		if err != nil {
			t.Errorf("error returned from ActivateAndServe, %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("could not shutdown test UDP server. Gave up waiting")
	}
}

func TestInProgressQueriesAtShutdownUDP(t *testing.T) {
	s, addr, _, err := RunLocalUDPServer(":0")
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}

	c := &Client{Net: "udp"}
	checkInProgressQueriesAtShutdownServer(t, s, addr, c)
}

func TestInProgressQueriesAtShutdownPacketConn(t *testing.T) {
	s, addr, _, err := RunLocalPacketConnServer(":0")
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}

	c := &Client{Net: "udp"}
	checkInProgressQueriesAtShutdownServer(t, s, addr, c)
}

func TestServerStartStopRace(t *testing.T) {
	var wg sync.WaitGroup
	for range 10 {
		wg.Add(1)
		s, _, _, err := RunLocalUDPServer(":0")
		if err != nil {
			t.Fatalf("could not start server: %s", err)
		}
		go func() {
			defer wg.Done()
			if err := s.Shutdown(); err != nil {
				t.Errorf("could not stop server: %s", err)
			}
		}()
	}
	wg.Wait()
}

func TestSocketOptions(t *testing.T) {
	if !supportsReuseAddr || !supportsReusePort {
		t.Skip("reuseaddr or reuseport is not supported")
	}

	testSocketOptions := func(t *testing.T, reuseAddr bool, reusePort bool) {
		wait := make(chan struct{})

		srv := &Server{
			Net:       "udp",
			Addr:      ":0",
			ReuseAddr: reuseAddr,
			ReusePort: reusePort,
		}

		srv.NotifyStartedFunc = func() {
			defer close(wait)

			conn, ok := srv.PacketConn.(*net.UDPConn)
			if !ok {
				t.Errorf("unexpected conn type: %T", srv.PacketConn)
				return
			}

			syscallConn, err := conn.SyscallConn()
			if err != nil {
				t.Errorf("cannot cast UDP conn to syscall conn: %v", err)
				return

			}

			err = syscallConn.Control(func(fd uintptr) {
				actualReusePort, err := checkReuseport(fd)
				if err != nil {
					t.Errorf("cannot get SO_REUSEPORT socket option: %v", err)
					return
				}

				if actualReusePort != reusePort {
					t.Errorf("SO_REUSEPORT is %v instead of %v", actualReusePort, reusePort)
				}

				actualReuseAddr, err := checkReuseaddr(fd)
				if err != nil {
					t.Errorf("cannot get SO_REUSEADDR socket option: %v", err)
					return
				}

				if actualReuseAddr != reuseAddr {
					t.Errorf("SO_REUSEADDR is %v instead of %v", actualReuseAddr, reusePort)
				}
			})
			if err != nil {
				t.Errorf("cannot check socket options: %v", err)
			}
		}

		fin := make(chan error, 1)
		go func() {
			fin <- srv.ListenAndServe()
		}()

		select {
		case <-wait:
			err := srv.Shutdown()
			if err != nil {
				t.Fatalf("cannot shutdown server: %v", err)
			}

			err = <-fin
			if err != nil {
				t.Fatalf("listen adn serve: %v", err)
			}
		case err := <-fin:
			t.Fatalf("listen adn serve: %v", err)
		}
	}

	t.Run("no socket options", func(t *testing.T) {
		testSocketOptions(t, false, false)
	})

	t.Run("SO_REUSEPORT", func(t *testing.T) {
		testSocketOptions(t, false, true)
	})

	t.Run("SO_REUSEADDR", func(t *testing.T) {
		testSocketOptions(t, true, false)
	})

	t.Run("SO_REUSEADDR and SO_REUSEPORT", func(t *testing.T) {
		testSocketOptions(t, true, true)
	})
}

func TestServerReuseport(t *testing.T) {
	if !supportsReusePort {
		t.Skip("reuseport is not supported")
	}

	startServer := func(addr string) (*Server, chan error) {
		wait := make(chan struct{})
		srv := &Server{
			Net:               "udp",
			Addr:              addr,
			NotifyStartedFunc: func() { close(wait) },
			ReusePort:         true,
		}

		fin := make(chan error, 1)
		go func() {
			fin <- srv.ListenAndServe()
		}()

		select {
		case <-wait:
		case err := <-fin:
			t.Fatalf("failed to start server: %v", err)
		}

		return srv, fin
	}

	srv1, fin1 := startServer(":0") // :0 is resolved to a random free port by the kernel
	srv2, fin2 := startServer(srv1.PacketConn.LocalAddr().String())

	if err := srv1.Shutdown(); err != nil {
		t.Fatalf("failed to shutdown first server: %v", err)
	}
	if err := srv2.Shutdown(); err != nil {
		t.Fatalf("failed to shutdown second server: %v", err)
	}

	if err := <-fin1; err != nil {
		t.Fatalf("first ListenAndServe returned error after Shutdown: %v", err)
	}
	if err := <-fin2; err != nil {
		t.Fatalf("second ListenAndServe returned error after Shutdown: %v", err)
	}
}

func TestServerReuseaddr(t *testing.T) {
	startServerFn := func(t *testing.T, network, addr string, expectSuccess bool) (*Server, chan error) {
		t.Helper()
		wait := make(chan struct{})
		srv := &Server{
			Net:               network,
			Addr:              addr,
			NotifyStartedFunc: func() { close(wait) },
			ReuseAddr:         true,
		}

		fin := make(chan error, 1)
		go func() {
			fin <- srv.ListenAndServe()
		}()

		select {
		case <-wait:
		case err := <-fin:

			if expectSuccess {
				t.Fatalf("%s: failed to start server: %v", t.Name(), err)
			}
			fin <- err
			return nil, fin
		}
		return srv, fin
	}

	externalIPFn := func(t *testing.T) (string, error) {
		t.Helper()
		ifaces, err := net.Interfaces()
		if err != nil {
			return "", err
		}
		for _, iface := range ifaces {
			if iface.Flags&net.FlagUp == 0 {
				continue // interface down
			}
			if iface.Flags&net.FlagLoopback != 0 {
				continue // loopback interface
			}
			addrs, err := iface.Addrs()
			if err != nil {
				return "", err
			}
			for _, addr := range addrs {
				var ip net.IP
				switch v := addr.(type) {
				case *net.IPNet:
					ip = v.IP
				case *net.IPAddr:
					ip = v.IP
				}
				if ip == nil || ip.IsLoopback() {
					continue
				}
				ip = ip.To4()
				if ip == nil {
					continue // not an ipv4 address
				}
				return ip.String(), nil
			}
		}
		return "", errors.New("are you connected to the network?")
	}

	freePortFn := func(t *testing.T) int {
		t.Helper()
		addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
		if err != nil {
			t.Fatalf("unable resolve tcp addr: %s", err)
		}

		l, err := net.ListenTCP("tcp", addr)
		if err != nil {
			t.Fatalf("unable listen tcp: %s", err)
		}
		defer l.Close()
		return l.Addr().(*net.TCPAddr).Port
	}

	t.Run("should-fail-tcp", func(t *testing.T) {
		// ReuseAddr should fail if you try to bind to exactly the same
		// combination of source address and port.
		// This should fail whether or not ReuseAddr is supported on a
		// particular OS
		ip, err := externalIPFn(t)
		if err != nil {
			t.Skip("no external IPs found")
			return
		}
		port := freePortFn(t)
		srv1, fin1 := startServerFn(t, "tcp", fmt.Sprintf("%s:%d", ip, port), true)
		srv2, fin2 := startServerFn(t, "tcp", fmt.Sprintf("%s:%d", ip, port), false)
		if srv2 != nil && srv2.started {
			t.Fatalf("second ListenAndServe should not have started")
		}
		if err := <-fin2; err == nil {
			t.Fatalf("second ListenAndServe should have returned a startup error: %v", err)
		}

		if err := srv1.Shutdown(); err != nil {
			t.Fatalf("failed to shutdown first server: %v", err)
		}
		if err := <-fin1; err != nil {
			t.Fatalf("first ListenAndServe returned error after Shutdown: %v", err)
		}
	})
	t.Run("should-succeed-tcp", func(t *testing.T) {
		if !supportsReuseAddr {
			t.Skip("reuseaddr is not supported")
		}
		ip, err := externalIPFn(t)
		if err != nil {
			t.Skip("no external IPs found")
			return
		}
		port := freePortFn(t)

		// ReuseAddr should succeed if you try to bind to the same port but a different source address
		srv1, fin1 := startServerFn(t, "tcp", fmt.Sprintf("localhost:%d", port), true)
		srv2, fin2 := startServerFn(t, "tcp", fmt.Sprintf("%s:%d", ip, port), true)

		if err := srv1.Shutdown(); err != nil {
			t.Fatalf("failed to shutdown first server: %v", err)
		}
		if err := srv2.Shutdown(); err != nil {
			t.Fatalf("failed to shutdown second server: %v", err)
		}
		if err := <-fin1; err != nil {
			t.Fatalf("first ListenAndServe returned error after Shutdown: %v", err)
		}
		if err := <-fin2; err != nil {
			t.Fatalf("second ListenAndServe returned error after Shutdown: %v", err)
		}
	})
	t.Run("should-succeed-udp", func(t *testing.T) {
		if !supportsReuseAddr {
			t.Skip("reuseaddr is not supported")
		}
		ip, err := externalIPFn(t)
		if err != nil {
			t.Skip("no external IPs found")
			return
		}
		port := freePortFn(t)

		// ReuseAddr should succeed if you try to bind to the same port but a different source address
		srv1, fin1 := startServerFn(t, "udp", fmt.Sprintf("localhost:%d", port), true)
		srv2, fin2 := startServerFn(t, "udp", fmt.Sprintf("%s:%d", ip, port), true)

		if err := srv1.Shutdown(); err != nil {
			t.Fatalf("failed to shutdown first server: %v", err)
		}
		if err := srv2.Shutdown(); err != nil {
			t.Fatalf("failed to shutdown second server: %v", err)
		}
		if err := <-fin1; err != nil {
			t.Fatalf("first ListenAndServe returned error after Shutdown: %v", err)
		}
		if err := <-fin2; err != nil {
			t.Fatalf("second ListenAndServe returned error after Shutdown: %v", err)
		}
	})
}

func TestServerRoundtripTsig(t *testing.T) {
	secret := map[Name]ByteField{mustParseName("test."): check1(BFFromBase64("so6ZGir4GPAqINNh9U5c3A=="))}

	s, addrstr, _, err := RunLocalUDPServer(":0", func(srv *Server) {
		srv.TsigSecret = secret
		srv.MsgAcceptFunc = func(dh Header) MsgAcceptAction {
			// defaultMsgAcceptFunc does reject UPDATE queries
			return MsgAccept
		}
	})
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer s.Shutdown()

	handlerFired := make(chan struct{})
	HandleFunc(mustParseName("example.com."), func(w ResponseWriter, r *Msg) {
		close(handlerFired)

		m := new(Msg)
		m.SetReply(r)
		if r.IsTsig() != nil {
			status := w.TsigStatus()
			if status == nil {
				// *Msg r has an TSIG record and it was validated
				m.SetTsig(mustParseName("test."), HmacSHA256, 300, time.Now().Unix())
			} else {
				// *Msg r has an TSIG records and it was not validated
				t.Errorf("invalid TSIG: %v", status)
			}
		} else {
			t.Error("missing TSIG")
		}
		if err := w.WriteMsg(m); err != nil {
			t.Error("writemsg failed", err)
		}
	})

	c := new(Client)
	m := new(Msg)
	m.Opcode = OpcodeUpdate
	m.SetQuestion(mustParseName("example.com."), TypeSOA)
	target, _ := NameFromString("bar.example.com.")
	m.Ns = []RR{&CNAME{
		Hdr: RR_Header{
			Name:   mustParseName("foo.example.com."),
			Rrtype: TypeCNAME,
			Class:  ClassINET,
			Ttl:    300,
		},
		Target: target,
	}}
	c.TsigSecret = secret
	m.SetTsig(mustParseName("test."), HmacSHA256, 300, time.Now().Unix())
	_, _, err = c.Exchange(m, addrstr)
	if err != nil {
		t.Fatal("failed to exchange", err)
	}
	select {
	case <-handlerFired:
		// ok, handler was actually called
	default:
		t.Error("handler was not called")
	}
}

func TestResponseAfterClose(t *testing.T) {
	testError := func(name string, err error) {
		t.Helper()

		expect := fmt.Sprintf("dns: %s called after Close", name)
		if err == nil {
			t.Errorf("expected error from %s after Close", name)
		} else if err.Error() != expect {
			t.Errorf("expected explicit error from %s after Close, expected %q, got %q", name, expect, err)
		}
	}

	rw := &response{
		closed: true,
	}

	_, err := rw.Write(make([]byte, 2))
	testError("Write", err)

	testError("WriteMsg", rw.WriteMsg(new(Msg)))
}

func TestResponseDoubleClose(t *testing.T) {
	rw := &response{
		closed: true,
	}
	if err, expect := rw.Close(), "dns: connection already closed"; err == nil || err.Error() != expect {
		t.Errorf("Close did not return expected: error %q, got: %v", expect, err)
	}
}

type countingConn struct {
	net.Conn
	writes int
}

func (c *countingConn) Write(p []byte) (int, error) {
	c.writes++
	return len(p), nil
}

func TestResponseWriteSinglePacket(t *testing.T) {
	c := &countingConn{}
	rw := &response{
		tcp: c,
	}
	rw.writer = rw

	m := new(Msg)
	m.SetQuestion(mustParseName("miek.nl."), TypeTXT)
	m.Response = true
	err := rw.WriteMsg(m)
	if err != nil {
		t.Fatalf("failed to write: %v", err)
	}

	if c.writes != 1 {
		t.Fatalf("incorrect number of Write calls")
	}
}

type ExampleFrameLengthWriter struct {
	Writer
}

func (e *ExampleFrameLengthWriter) Write(m []byte) (int, error) {
	fmt.Println("writing raw DNS message of length", len(m))
	return e.Writer.Write(m)
}

func ExampleDecorateWriter() {
	// instrument raw DNS message writing
	wf := DecorateWriter(func(w Writer) Writer {
		return &ExampleFrameLengthWriter{w}
	})

	// simple UDP server
	pc, err := net.ListenPacket("udp", ":0")
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	server := &Server{
		PacketConn:     pc,
		DecorateWriter: wf,
		ReadTimeout:    time.Hour, WriteTimeout: time.Hour,
	}

	waitLock := sync.Mutex{}
	waitLock.Lock()
	server.NotifyStartedFunc = waitLock.Unlock
	defer server.Shutdown()

	go func() {
		server.ActivateAndServe()
		pc.Close()
	}()

	waitLock.Lock()

	HandleFunc(mustParseName("miek.nl."), HelloServer)

	c := new(Client)
	m := new(Msg)
	m.SetQuestion(mustParseName("miek.nl."), TypeTXT)
	_, _, err = c.Exchange(m, pc.LocalAddr().String())
	if err != nil {
		fmt.Println("failed to exchange", err.Error())
		return
	}
	// Output: writing raw DNS message of length 56
}

var (
	// CertPEMBlock is a X509 data used to test TLS servers (used with tls.X509KeyPair)
	CertPEMBlock = []byte(`-----BEGIN CERTIFICATE-----
MIIDAzCCAeugAwIBAgIRAJFYMkcn+b8dpU15wjf++GgwDQYJKoZIhvcNAQELBQAw
EjEQMA4GA1UEChMHQWNtZSBDbzAeFw0xNjAxMDgxMjAzNTNaFw0xNzAxMDcxMjAz
NTNaMBIxEDAOBgNVBAoTB0FjbWUgQ28wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
ggEKAoIBAQDXjqO6skvP03k58CNjQggd9G/mt+Wa+xRU+WXiKCCHttawM8x+slq5
yfsHCwxlwsGn79HmJqecNqgHb2GWBXAvVVokFDTcC1hUP4+gp2gu9Ny27UHTjlLm
O0l/xZ5MN8tfKyYlFw18tXu3fkaPyHj8v/D1RDkuo4ARdFvGSe8TqisbhLk2+9ow
xfIGbEM9Fdiw8qByC2+d+FfvzIKz3GfQVwn0VoRom8L6NBIANq1IGrB5JefZB6nv
DnfuxkBmY7F1513HKuEJ8KsLWWZWV9OPU4j4I4Rt+WJNlKjbD2srHxyrS2RDsr91
8nCkNoWVNO3sZq0XkWKecdc921vL4ginAgMBAAGjVDBSMA4GA1UdDwEB/wQEAwIC
pDATBgNVHSUEDDAKBggrBgEFBQcDATAPBgNVHRMBAf8EBTADAQH/MBoGA1UdEQQT
MBGCCWxvY2FsaG9zdIcEfwAAATANBgkqhkiG9w0BAQsFAAOCAQEAGcU3iyLBIVZj
aDzSvEDHUd1bnLBl1C58Xu/CyKlPqVU7mLfK0JcgEaYQTSX6fCJVNLbbCrcGLsPJ
fbjlBbyeLjTV413fxPVuona62pBFjqdtbli2Qe8FRH2KBdm41JUJGdo+SdsFu7nc
BFOcubdw6LLIXvsTvwndKcHWx1rMX709QU1Vn1GAIsbJV/DWI231Jyyb+lxAUx/C
8vce5uVxiKcGS+g6OjsN3D3TtiEQGSXLh013W6Wsih8td8yMCMZ3w8LQ38br1GUe
ahLIgUJ9l6HDguM17R7kGqxNvbElsMUHfTtXXP7UDQUiYXDakg8xDP6n9DCDhJ8Y
bSt7OLB7NQ==
-----END CERTIFICATE-----`)

	// KeyPEMBlock is a X509 data used to test TLS servers (used with tls.X509KeyPair)
	KeyPEMBlock = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEA146jurJLz9N5OfAjY0IIHfRv5rflmvsUVPll4iggh7bWsDPM
frJaucn7BwsMZcLBp+/R5iannDaoB29hlgVwL1VaJBQ03AtYVD+PoKdoLvTctu1B
045S5jtJf8WeTDfLXysmJRcNfLV7t35Gj8h4/L/w9UQ5LqOAEXRbxknvE6orG4S5
NvvaMMXyBmxDPRXYsPKgcgtvnfhX78yCs9xn0FcJ9FaEaJvC+jQSADatSBqweSXn
2Qep7w537sZAZmOxdeddxyrhCfCrC1lmVlfTj1OI+COEbfliTZSo2w9rKx8cq0tk
Q7K/dfJwpDaFlTTt7GatF5FinnHXPdtby+IIpwIDAQABAoIBAAJK4RDmPooqTJrC
JA41MJLo+5uvjwCT9QZmVKAQHzByUFw1YNJkITTiognUI0CdzqNzmH7jIFs39ZeG
proKusO2G6xQjrNcZ4cV2fgyb5g4QHStl0qhs94A+WojduiGm2IaumAgm6Mc5wDv
ld6HmknN3Mku/ZCyanVFEIjOVn2WB7ZQLTBs6ZYaebTJG2Xv6p9t2YJW7pPQ9Xce
s9ohAWohyM4X/OvfnfnLtQp2YLw/BxwehBsCR5SXM3ibTKpFNtxJC8hIfTuWtxZu
2ywrmXShYBRB1WgtZt5k04bY/HFncvvcHK3YfI1+w4URKtwdaQgPUQRbVwDwuyBn
flfkCJECgYEA/eWt01iEyE/lXkGn6V9lCocUU7lCU6yk5UT8VXVUc5If4KZKPfCk
p4zJDOqwn2eM673aWz/mG9mtvAvmnugaGjcaVCyXOp/D/GDmKSoYcvW5B/yjfkLy
dK6Yaa5LDRVYlYgyzcdCT5/9Qc626NzFwKCZNI4ncIU8g7ViATRxWJ8CgYEA2Ver
vZ0M606sfgC0H3NtwNBxmuJ+lIF5LNp/wDi07lDfxRR1rnZMX5dnxjcpDr/zvm8J
WtJJX3xMgqjtHuWKL3yKKony9J5ZPjichSbSbhrzfovgYIRZLxLLDy4MP9L3+CX/
yBXnqMWuSnFX+M5fVGxdDWiYF3V+wmeOv9JvavkCgYEAiXAPDFzaY+R78O3xiu7M
r0o3wqqCMPE/wav6O/hrYrQy9VSO08C0IM6g9pEEUwWmzuXSkZqhYWoQFb8Lc/GI
T7CMXAxXQLDDUpbRgG79FR3Wr3AewHZU8LyiXHKwxcBMV4WGmsXGK3wbh8fyU1NO
6NsGk+BvkQVOoK1LBAPzZ1kCgYEAsBSmD8U33T9s4dxiEYTrqyV0lH3g/SFz8ZHH
pAyNEPI2iC1ONhyjPWKlcWHpAokiyOqeUpVBWnmSZtzC1qAydsxYB6ShT+sl9BHb
RMix/QAauzBJhQhUVJ3OIys0Q1UBDmqCsjCE8SfOT4NKOUnA093C+YT+iyrmmktZ
zDCJkckCgYEAndqM5KXGk5xYo+MAA1paZcbTUXwaWwjLU+XSRSSoyBEi5xMtfvUb
7+a1OMhLwWbuz+pl64wFKrbSUyimMOYQpjVE/1vk/kb99pxbgol27hdKyTH1d+ov
kFsxKCqxAnBVGEWAvVZAiiTOxleQFjz5RnL0BQp9Lg2cQe+dvuUmIAA=
-----END RSA PRIVATE KEY-----`)
)
