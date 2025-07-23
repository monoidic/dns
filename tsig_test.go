package dns

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func newTsig(algo Name) *Msg {
	m := new(Msg)
	m.SetQuestion(mustParseName("example.org."), TypeA)
	m.SetTsig(mustParseName("example."), algo, 300, time.Now().Unix())
	return m
}

func TestTsig(t *testing.T) {
	m := newTsig(HmacSHA256)
	buf, _, err := TsigGenerate(m, check1(BFFromBase64("pRZgBrBvI4NAHZYhxmhs/Q==")), ByteField{}, false)
	if err != nil {
		t.Fatal(err)
	}
	err = TsigVerify(buf, check1(BFFromBase64("pRZgBrBvI4NAHZYhxmhs/Q==")), ByteField{}, false)
	if err != nil {
		t.Fatal(err)
	}

	// TSIG accounts for ID substitution. This means if the message ID is
	// changed by a forwarder, we should still be able to verify the TSIG.
	m = newTsig(HmacSHA256)
	buf, _, err = TsigGenerate(m, check1(BFFromBase64("pRZgBrBvI4NAHZYhxmhs/Q==")), ByteField{}, false)
	if err != nil {
		t.Fatal(err)
	}

	binary.BigEndian.PutUint16(buf[0:2], 42)
	err = TsigVerify(buf, check1(BFFromBase64("pRZgBrBvI4NAHZYhxmhs/Q==")), ByteField{}, false)
	if err != nil {
		t.Fatal(err)
	}
}

func TestTsigCase(t *testing.T) {
	m := newTsig(mustParseName(strings.ToUpper(HmacSHA256.String())))
	buf, _, err := TsigGenerate(m, check1(BFFromBase64("pRZgBrBvI4NAHZYhxmhs/Q==")), ByteField{}, false)
	if err != nil {
		t.Fatal(err)
	}
	err = TsigVerify(buf, check1(BFFromBase64("pRZgBrBvI4NAHZYhxmhs/Q==")), ByteField{}, false)
	if err != nil {
		t.Fatal(err)
	}
}

func TestTsigErrorResponse(t *testing.T) {
	for _, rcode := range []uint16{RcodeBadSig, RcodeBadKey} {
		m := newTsig(mustParseName(strings.ToUpper(HmacSHA256.String())))
		m.IsTsig().Error = rcode
		buf, _, err := TsigGenerate(m, check1(BFFromBase64("pRZgBrBvI4NAHZYhxmhs/Q==")), ByteField{}, false)
		if err != nil {
			t.Fatal(err)
		}

		err = m.Unpack(buf)
		if err != nil {
			t.Fatal(err)
		}

		mTsig := m.IsTsig()
		if mTsig.MAC.EncodedLen() != 0 {
			t.Error("Expected empty MAC")
		}
		if mTsig.MACSize != 0 {
			t.Error("Expected 0 MACSize")
		}
		if mTsig.TimeSigned != 0 {
			t.Errorf("Expected TimeSigned to be 0, got %v", mTsig.TimeSigned)
		}
	}
}

func TestTsigBadTimeResponse(t *testing.T) {
	clientTime := uint64(time.Now().Unix()) - 3600
	m := newTsig(mustParseName(strings.ToUpper(HmacSHA256.String())))
	m.IsTsig().Error = RcodeBadTime
	m.IsTsig().TimeSigned = clientTime

	buf, _, err := TsigGenerate(m, check1(BFFromBase64("pRZgBrBvI4NAHZYhxmhs/Q==")), ByteField{}, false)
	if err != nil {
		t.Fatal(err)
	}

	err = m.Unpack(buf)
	if err != nil {
		t.Fatal(err)
	}

	mTsig := m.IsTsig()
	if mTsig.MAC.EncodedLen() == 0 {
		t.Error("Expected non-empty MAC")
	}
	if int(mTsig.MACSize) != mTsig.MAC.EncodedLen() {
		t.Errorf("Expected MACSize %v, got %v", mTsig.MAC.EncodedLen(), mTsig.MACSize)
	}

	if mTsig.TimeSigned != clientTime {
		t.Errorf("Expected TimeSigned %v to be retained, got %v", clientTime, mTsig.TimeSigned)
	}
}

const (
	// A template wire-format DNS message (in hex form) containing a TSIG RR.
	// Its time signed field will be filled by tests.
	wireMsg = "c60028000001000000010001076578616d706c6503636f6d00000600010161c00c0001000100000e100004c0000201077465" +
		"73746b65790000fa00ff00000000003d0b686d61632d73686132353600" +
		"%012x" + // placeholder for the "time signed" field
		"012c00208cf23e0081d915478a182edcea7ff48ad102948e6c7ef8e887536957d1fa5616c60000000000"
	// A secret (in base64 format) with which the TSIG in wireMsg will be validated
	// the 'time signed' field value that would make the TSIG RR valid with testSecret
	timeSigned uint64 = 1594855491
)

var testSecret = check1(BFFromBase64("NoTCJU+DMqFWywaPyxSijrDEA/eC3nK0xi3AMEZuPVk="))

func TestTsigErrors(t *testing.T) {
	// Helper shortcut to build wire-format test message.
	// TsigVerify can modify the slice, so we need to create a new one for each test case below.
	buildMsgData := func(tm uint64) []byte {
		msgData, err := hex.DecodeString(fmt.Sprintf(wireMsg, tm))
		if err != nil {
			t.Fatal(err)
		}
		return msgData
	}

	// the signature is valid but 'time signed' is too far from the "current time".
	if err := tsigVerify(buildMsgData(timeSigned), tsigHMACProvider(testSecret), ByteField{}, false, timeSigned+301); err != ErrTime {
		t.Fatalf("expected an error '%v' but got '%v'", ErrTime, err)
	}
	if err := tsigVerify(buildMsgData(timeSigned), tsigHMACProvider(testSecret), ByteField{}, false, timeSigned-301); err != ErrTime {
		t.Fatalf("expected an error '%v' but got '%v'", ErrTime, err)
	}

	// the signature is invalid and 'time signed' is too far.
	// the signature should be checked first, so we should see ErrSig.
	if err := tsigVerify(buildMsgData(timeSigned+301), tsigHMACProvider(testSecret), ByteField{}, false, timeSigned); err != ErrSig {
		t.Fatalf("expected an error '%v' but got '%v'", ErrSig, err)
	}

	// tweak the algorithm name in the wire data, resulting in the "unknown algorithm" error.
	msgData := buildMsgData(timeSigned)
	copy(msgData[67:], "bogus")
	if err := tsigVerify(msgData, tsigHMACProvider(testSecret), ByteField{}, false, timeSigned); err != ErrKeyAlg {
		t.Fatalf("expected an error '%v' but got '%v'", ErrKeyAlg, err)
	}

	// call TsigVerify with a message that doesn't contain a TSIG
	msgData, tsig, err := stripTsig(buildMsgData(timeSigned))
	if err != nil {
		t.Fatal(err)
	}
	if err := tsigVerify(msgData, tsigHMACProvider(testSecret), ByteField{}, false, timeSigned); err != ErrNoSig {
		t.Fatalf("expected an error '%v' but got '%v'", ErrNoSig, err)
	}

	// replace the test TSIG with a bogus one with large "other data", which would cause overflow in TsigVerify.
	// The overflow should be caught without disruption.
	tsig.OtherData = BFFromBytes(make([]byte, 4096))
	tsig.OtherLen = uint16(tsig.OtherData.EncodedLen())
	msg := new(Msg)
	if err = msg.Unpack(msgData); err != nil {
		t.Fatal(err)
	}
	msg.Extra = append(msg.Extra, tsig)
	if msgData, err = msg.Pack(); err != nil {
		t.Fatal(err)
	}
	err = tsigVerify(msgData, tsigHMACProvider(testSecret), ByteField{}, false, timeSigned)
	if err == nil || !strings.Contains(err.Error(), "buffer size too small") {
		t.Errorf("expected error to contain %q, but got %v", "buffer size too small", err)
	}
}

// This test exercises some more corner cases for TsigGenerate.
func TestTsigGenerate(t *testing.T) {
	// This is a template TSIG to be used for signing.
	tsig := TSIG{
		Hdr:        RR_Header{Name: mustParseName("testkey."), Rrtype: TypeTSIG, Class: ClassANY, Ttl: 0},
		Algorithm:  HmacSHA256,
		TimeSigned: timeSigned,
		Fudge:      300,
		OrigId:     42,
		Error:      RcodeBadTime, // use a non-0 value to make sure it's indeed used
	}

	tests := []struct {
		desc        string // test description
		requestMAC  string // request MAC to be passed to TsigGenerate (arbitrary choice)
		otherData   string // other data specified in the TSIG (arbitrary choice)
		expectedMAC string // pre-computed expected (correct) MAC in hex form
	}{
		{
			"with request MAC", "3684c225", "",
			"C110E3F62694755C10761DC8717462431EE34340B7C9D1EEE09449150757C5B1",
		},
		{
			"no request MAC", "", "",
			"385449A425C6D52B9BF2C65C0726EEFA0AD8084CDAF488F24547E686605B9610",
		},
		{
			"with other data", "3684c225", "666f6f",
			"15B91571CA80B3B410A77E2B44F8CC4F35ACE22B26020138439DD94803E23B5D",
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.desc, func(t *testing.T) {
			// Build TSIG for signing from the template
			testTSIG := tsig
			testTSIG.OtherLen = uint16(len(tc.otherData) / 2)
			testTSIG.OtherData = check1(BFFromHex(tc.otherData))
			req := &Msg{
				MsgHdr:   MsgHdr{Opcode: OpcodeUpdate},
				Question: []Question{{Name: mustParseName("example.com."), Qtype: TypeSOA, Qclass: ClassINET}},
				Extra:    []RR{&testTSIG},
			}

			// Call generate, and check the returned MAC against the expected value
			msgData, mac, err := TsigGenerate(req, testSecret, check1(BFFromHex(tc.requestMAC)), false)
			if err != nil {
				t.Error(err)
			}
			if mac.Hex() != tc.expectedMAC {
				t.Fatalf("MAC doesn't match: expected '%s', but got '%s'", tc.expectedMAC, mac.Hex())
			}

			// Retrieve the TSIG to be sent out, confirm the MAC in it
			_, outTSIG, err := stripTsig(msgData)
			if err != nil {
				t.Error(err)
			}
			if outTSIG.MAC.Hex() != tc.expectedMAC {
				t.Fatalf("MAC doesn't match: expected '%s', but got '%s'", tc.expectedMAC, outTSIG.MAC.Hex())
			}
			// Confirm other fields of MAC.
			// RDLENGTH should be valid as stripTsig succeeded, so we exclude it from comparison
			outTSIG.MACSize = 0
			outTSIG.MAC = ByteField{}
			testTSIG.Hdr.Rdlength = outTSIG.Hdr.Rdlength
			if *outTSIG != testTSIG {
				t.Fatalf("TSIG RR doesn't match: expected '%v', but got '%v'", *outTSIG, testTSIG)
			}
		})
	}
}

func TestTSIGHMAC224And384(t *testing.T) {
	tests := []struct {
		algorithm   Name   // TSIG algorithm, also used as test description
		secret      string // (arbitrarily chosen) secret suitable for the algorithm in base64 format
		expectedMAC string // pre-computed expected (correct) MAC in hex form
	}{
		{
			HmacSHA224, "hVEkQuAqnTmBuRrT9KF1Udr91gOMGWPw9LaTtw==",
			"D6DAF9EA189E48BC38F9AED63D6CC4140CDFA38A7A333EE2EEFDBD31",
		},
		{
			HmacSHA384, "Qjer2TL2lAdpq9w6Gjs98/ClCQx/L3vtgVHCmrZ8l/oKEPjqUUMFO18gMCRwd5H4",
			"89A48936D29187870C325CBDBA5AD71609BD038D0459D6010C844D659C570E881D3650E4FE7310BE53EBE5178D0D1001",
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.algorithm.String(), func(t *testing.T) {
			// Build a DNS message with TSIG for the test scenario
			tsig := TSIG{
				Hdr:        RR_Header{Name: mustParseName("testkey."), Rrtype: TypeTSIG, Class: ClassANY, Ttl: 0},
				Algorithm:  tc.algorithm,
				TimeSigned: timeSigned,
				Fudge:      300,
				OrigId:     42,
			}
			req := &Msg{
				MsgHdr:   MsgHdr{Opcode: OpcodeUpdate},
				Question: []Question{{Name: mustParseName("example.com."), Qtype: TypeSOA, Qclass: ClassINET}},
				Extra:    []RR{&tsig},
			}

			// Confirm both Generate and Verify recognize the algorithm and handle it correctly
			msgData, mac, err := TsigGenerate(req, check1(BFFromBase64(tc.secret)), ByteField{}, false)
			if err != nil {
				t.Error(err)
			}
			if mac.Hex() != tc.expectedMAC {
				t.Fatalf("MAC doesn't match: expected '%s' but got '%s'", tc.expectedMAC, mac.Hex())
			}
			if err = tsigVerify(msgData, tsigHMACProvider(check1(BFFromBase64(tc.secret))), ByteField{}, false, timeSigned); err != nil {
				t.Error(err)
			}
		})
	}
}

var testGoodKeyName = mustParseName("goodkey.")

var (
	errBadKey   = errors.New("this is an intentional error")
	testGoodMAC = []byte{0, 1, 2, 3}
)

// testProvider always generates the same MAC and only accepts the one signature
type testProvider struct {
	GenerateAllKeys bool
}

func (provider *testProvider) Generate(_ []byte, t *TSIG) ([]byte, error) {
	if t.Hdr.Name == testGoodKeyName || provider.GenerateAllKeys {
		return testGoodMAC, nil
	}
	return nil, errBadKey
}

func (*testProvider) Verify(_ []byte, t *TSIG) error {
	if t.Hdr.Name == testGoodKeyName {
		return nil
	}
	return errBadKey
}

func TestTsigGenerateProvider(t *testing.T) {
	tables := []struct {
		keyname Name
		mac     []byte
		err     error
	}{
		{
			testGoodKeyName,
			testGoodMAC,
			nil,
		},
		{
			mustParseName("badkey."),
			nil,
			errBadKey,
		},
	}

	for _, table := range tables {
		t.Run(table.keyname.String(), func(t *testing.T) {
			tsig := TSIG{
				Hdr:        RR_Header{Name: table.keyname, Rrtype: TypeTSIG, Class: ClassANY, Ttl: 0},
				Algorithm:  HmacSHA1,
				TimeSigned: timeSigned,
				Fudge:      300,
				OrigId:     42,
			}
			req := &Msg{
				MsgHdr:   MsgHdr{Opcode: OpcodeUpdate},
				Question: []Question{{Name: mustParseName("example.com."), Qtype: TypeSOA, Qclass: ClassINET}},
				Extra:    []RR{&tsig},
			}

			_, mac, err := TsigGenerateWithProvider(req, new(testProvider), ByteField{}, false)
			if err != table.err {
				t.Fatalf("error doesn't match: expected '%s' but got '%s'", table.err, err)
			}
			expectedMAC := hex.EncodeToString(table.mac)
			if mac.Hex() != expectedMAC {
				t.Fatalf("MAC doesn't match: expected '%s' but got '%s'", expectedMAC, mac.Hex())
			}
		})
	}
}

func TestTsigVerifyProvider(t *testing.T) {
	tables := []struct {
		keyname Name
		err     error
	}{
		{
			testGoodKeyName,
			nil,
		},
		{
			mustParseName("badkey."),
			errBadKey,
		},
	}

	for _, table := range tables {
		t.Run(table.keyname.String(), func(t *testing.T) {
			tsig := TSIG{
				Hdr:        RR_Header{Name: table.keyname, Rrtype: TypeTSIG, Class: ClassANY, Ttl: 0},
				Algorithm:  HmacSHA1,
				TimeSigned: timeSigned,
				Fudge:      300,
				OrigId:     42,
			}
			req := &Msg{
				MsgHdr:   MsgHdr{Opcode: OpcodeUpdate},
				Question: []Question{{Name: mustParseName("example.com."), Qtype: TypeSOA, Qclass: ClassINET}},
				Extra:    []RR{&tsig},
			}

			provider := &testProvider{true}
			msgData, _, err := TsigGenerateWithProvider(req, provider, ByteField{}, false)
			if err != nil {
				t.Error(err)
			}
			if err = tsigVerify(msgData, provider, ByteField{}, false, timeSigned); err != table.err {
				t.Fatalf("error doesn't match: expected '%s' but got '%s'", table.err, err)
			}
		})
	}
}
