package dns

import (
	"crypto/tls"
	"errors"
	"testing"
	"time"
)

var (
	tsigSecret  = map[Name]ByteField{mustParseName("axfr."): check1(BFFromBase64("so6ZGir4GPAqINNh9U5c3A=="))}
	xfrSoa      = testRR(`miek.nl.	0	IN	SOA	linode.atoom.net. miek.miek.nl. 2009032802 21600 7200 604800 3600`)
	xfrA        = testRR(`x.miek.nl.	1792	IN	A	10.0.0.1`)
	xfrMX       = testRR(`miek.nl.	1800	IN	MX	1	x.miek.nl.`)
	xfrTestData = []RR{xfrSoa, xfrA, xfrMX, xfrSoa}
)

func InvalidXfrServer(w ResponseWriter, req *Msg) {
	ch := make(chan *Envelope)
	tr := new(Transfer)

	go tr.Out(w, req, ch)
	ch <- &Envelope{RR: []RR{}}
	close(ch)
	w.Hijack()
}

func SingleEnvelopeXfrServer(w ResponseWriter, req *Msg) {
	ch := make(chan *Envelope)
	tr := new(Transfer)

	go tr.Out(w, req, ch)
	ch <- &Envelope{RR: xfrTestData}
	close(ch)
	w.Hijack()
}

func MultipleEnvelopeXfrServer(w ResponseWriter, req *Msg) {
	ch := make(chan *Envelope)
	tr := new(Transfer)

	go tr.Out(w, req, ch)

	for _, rr := range xfrTestData {
		ch <- &Envelope{RR: []RR{rr}}
	}
	close(ch)
	w.Hijack()
}

func TestInvalidXfr(t *testing.T) {
	HandleFunc(mustParseName("miek.nl."), InvalidXfrServer)
	defer HandleRemove(mustParseName("miek.nl."))

	s, addrstr, _, err := RunLocalTCPServer(":0")
	if err != nil {
		t.Fatalf("unable to run test server: %s", err)
	}
	defer s.Shutdown()

	tr := new(Transfer)
	m := new(Msg)
	m.SetAxfr(mustParseName("miek.nl."))

	c, err := tr.In(m, addrstr)
	if err != nil {
		t.Fatal("failed to zone transfer in", err)
	}

	for msg := range c {
		if msg.Error == nil {
			t.Fatal("failed to catch 'no SOA' error")
		}
	}
}

func TestSingleEnvelopeXfr(t *testing.T) {
	HandleFunc(mustParseName("miek.nl."), SingleEnvelopeXfrServer)
	defer HandleRemove(mustParseName("miek.nl."))

	s, addrstr, _, err := RunLocalTCPServer(":0", func(srv *Server) {
		srv.TsigSecret = tsigSecret
	})
	if err != nil {
		t.Fatalf("unable to run test server: %s", err)
	}
	defer s.Shutdown()

	axfrTestingSuite(t, addrstr)
}

func TestSingleEnvelopeXfrTLS(t *testing.T) {
	HandleFunc(mustParseName("miek.nl."), SingleEnvelopeXfrServer)
	defer HandleRemove(mustParseName("miek.nl."))

	cert, err := tls.X509KeyPair(CertPEMBlock, KeyPEMBlock)
	if err != nil {
		t.Fatalf("unable to build certificate: %v", err)
	}

	tlsConfig := tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	s, addrstr, _, err := RunLocalTLSServer(":0", &tlsConfig)
	if err != nil {
		t.Fatalf("unable to run test server: %s", err)
	}
	defer s.Shutdown()

	axfrTestingSuiteTLS(t, addrstr)
}

func TestMultiEnvelopeXfr(t *testing.T) {
	HandleFunc(mustParseName("miek.nl."), MultipleEnvelopeXfrServer)
	defer HandleRemove(mustParseName("miek.nl."))

	s, addrstr, _, err := RunLocalTCPServer(":0", func(srv *Server) {
		srv.TsigSecret = tsigSecret
	})
	if err != nil {
		t.Fatalf("unable to run test server: %s", err)
	}
	defer s.Shutdown()

	axfrTestingSuite(t, addrstr)
}

func axfrTestingSuite(t *testing.T, addrstr string) {
	tr := new(Transfer)
	m := new(Msg)
	m.SetAxfr(mustParseName("miek.nl."))

	c, err := tr.In(m, addrstr)
	if err != nil {
		t.Fatal("failed to zone transfer in", err)
	}

	var records []RR
	for msg := range c {
		if msg.Error != nil {
			t.Fatal(msg.Error)
		}
		records = append(records, msg.RR...)
	}

	if len(records) != len(xfrTestData) {
		t.Fatalf("bad axfr: expected %v, got %v", records, xfrTestData)
	}

	for i, rr := range records {
		if !IsDuplicate(rr, xfrTestData[i]) {
			t.Fatalf("bad axfr: expected %v, got %v", records, xfrTestData)
		}
	}
}

func axfrTestingSuiteTLS(t *testing.T, addrstr string) {
	tr := new(Transfer)
	m := new(Msg)
	m.SetAxfr(mustParseName("miek.nl."))

	tr.TLS = &tls.Config{
		InsecureSkipVerify: true,
	}
	c, err := tr.In(m, addrstr)
	if err != nil {
		t.Fatal("failed to zone transfer in", err)
	}

	var records []RR
	for msg := range c {
		if msg.Error != nil {
			t.Fatal(msg.Error)
		}
		records = append(records, msg.RR...)
	}

	if len(records) != len(xfrTestData) {
		t.Fatalf("bad axfr: expected %v, got %v", records, xfrTestData)
	}

	for i, rr := range records {
		if !IsDuplicate(rr, xfrTestData[i]) {
			t.Fatalf("bad axfr: expected %v, got %v", records, xfrTestData)
		}
	}
}

func axfrTestingSuiteWithCustomTsig(t *testing.T, addrstr string, provider TsigProvider) {
	tr := new(Transfer)
	m := new(Msg)
	var err error
	tr.Conn, err = Dial("tcp", addrstr)
	if err != nil {
		t.Fatal("failed to dial", err)
	}
	tr.TsigProvider = provider
	m.SetAxfr(mustParseName("miek.nl."))
	m.SetTsig(mustParseName("axfr."), HmacSHA256, 300, time.Now().Unix())

	c, err := tr.In(m, addrstr)
	if err != nil {
		t.Fatal("failed to zone transfer in", err)
	}

	var records []RR
	for msg := range c {
		if msg.Error != nil {
			t.Fatal(msg.Error)
		}
		records = append(records, msg.RR...)
	}

	if len(records) != len(xfrTestData) {
		t.Fatalf("bad axfr: expected %v, got %v", records, xfrTestData)
	}

	for i, rr := range records {
		if !IsDuplicate(rr, xfrTestData[i]) {
			t.Errorf("bad axfr: expected %v, got %v", records, xfrTestData)
		}
	}
}

func axfrTestingSuiteWithMsgNotSigned(t *testing.T, addrstr string, provider TsigProvider) {
	tr := new(Transfer)
	m := new(Msg)
	var err error
	tr.Conn, err = Dial("tcp", addrstr)
	if err != nil {
		t.Fatal("failed to dial", err)
	}
	tr.TsigProvider = provider
	m.SetAxfr(mustParseName("miek.nl."))

	c, err := tr.In(m, addrstr)
	if err != nil {
		t.Fatal("failed to zone transfer in", err)
	}

	for msg := range c {
		if !errors.Is(msg.Error, ErrNoSig) {
			t.Fatal("expecting ErrNoSig error")
		}
	}
}

func TestCustomTsigProvider(t *testing.T) {
	HandleFunc(mustParseName("miek.nl."), SingleEnvelopeXfrServer)
	defer HandleRemove(mustParseName("miek.nl."))

	s, addrstr, _, err := RunLocalTCPServer(":0", func(srv *Server) {
		srv.TsigProvider = tsigSecretProvider(tsigSecret)
	})
	if err != nil {
		t.Fatalf("unable to run test server: %s", err)
	}
	defer s.Shutdown()

	axfrTestingSuiteWithCustomTsig(t, addrstr, tsigSecretProvider(tsigSecret))
}

func TestTSIGNotSigned(t *testing.T) {
	HandleFunc(mustParseName("miek.nl."), SingleEnvelopeXfrServer)
	defer HandleRemove(mustParseName("miek.nl."))

	s, addrstr, _, err := RunLocalTCPServer(":0")
	if err != nil {
		t.Fatalf("unable to run test server: %s", err)
	}
	defer s.Shutdown()

	axfrTestingSuiteWithMsgNotSigned(t, addrstr, tsigSecretProvider(tsigSecret))
}
