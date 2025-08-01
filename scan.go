package dns

import (
	"bufio"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
)

const maxTok = 512 // Token buffer start size, and growth size amount.

// The maximum depth of $INCLUDE directives supported by the
// ZoneParser API.
const maxIncludeDepth = 7

// Tokenize a RFC 1035 zone file. The tokenizer will normalize it:
// * Add ownernames if they are left blank;
// * Suppress sequences of spaces;
// * Make each RR fit on one line (_NEWLINE is send as last)
// * Handle comments: ;
// * Handle braces - anywhere.
const (
	// Zonefile
	zEOF = iota
	zString
	zBlank
	zQuote
	zNewline
	zRrtpe
	zOwner
	zClass
	zDirOrigin   // $ORIGIN
	zDirTTL      // $TTL
	zDirInclude  // $INCLUDE
	zDirGenerate // $GENERATE

	// Privatekey file
	zValue
	zKey

	zExpectOwnerDir      // Ownername
	zExpectOwnerBl       // Whitespace after the ownername
	zExpectAny           // Expect rrtype, ttl or class
	zExpectAnyNoClass    // Expect rrtype or ttl
	zExpectAnyNoClassBl  // The whitespace after _EXPECT_ANY_NOCLASS
	zExpectAnyNoTTL      // Expect rrtype or class
	zExpectAnyNoTTLBl    // Whitespace after _EXPECT_ANY_NOTTL
	zExpectRrtype        // Expect rrtype
	zExpectRrtypeBl      // Whitespace BEFORE rrtype
	zExpectRdata         // The first element of the rdata
	zExpectDirTTLBl      // Space after directive $TTL
	zExpectDirTTL        // Directive $TTL
	zExpectDirOriginBl   // Space after directive $ORIGIN
	zExpectDirOrigin     // Directive $ORIGIN
	zExpectDirIncludeBl  // Space after directive $INCLUDE
	zExpectDirInclude    // Directive $INCLUDE
	zExpectDirGenerate   // Directive $GENERATE
	zExpectDirGenerateBl // Space after directive $GENERATE
)

// ParseError is a parsing error. It contains the parse error and the location in the io.Reader
// where the error occurred.
type ParseError struct {
	file       string
	err        string
	wrappedErr error
	lex        lex
}

func (e *ParseError) Error() (s string) {
	if e.file != "" {
		s = e.file + ": "
	}
	if e.err == "" && e.wrappedErr != nil {
		e.err = e.wrappedErr.Error()
	}
	s += "dns: " + e.err + ": " + strconv.QuoteToASCII(e.lex.token) + " at line: " +
		strconv.Itoa(e.lex.line) + ":" + strconv.Itoa(e.lex.column)
	return
}

func (e *ParseError) Unwrap() error { return e.wrappedErr }

type lex struct {
	token  string // text of the token
	err    bool   // when true, token text has lexer error
	value  uint8  // value: zString, _BLANK, etc.
	torc   uint16 // type or class as parsed in the lexer, we only need to look this up in the grammar
	line   int    // line in the file
	column int    // column in the file
}

// ttlState describes the state necessary to fill in an omitted RR TTL
type ttlState struct {
	ttl           uint32 // ttl is the current default TTL
	isByDirective bool   // isByDirective indicates whether ttl was set by a $TTL directive
}

// NewRR reads a string s and returns the first RR.
// If s contains no records, NewRR will return nil with no error.
//
// The class defaults to IN, TTL defaults to 3600, and
// origin for resolving relative domain names defaults to the DNS root (.).
// Full zone file syntax is supported, including directives like $TTL and $ORIGIN.
// All fields of the returned RR are set from the read data, except RR.Header().Rdlength which is set to 0.
// Is you need a partial resource record with no rdata - for instance - for dynamic updates, see the [ANY]
// documentation.
func NewRR(s string) (RR, error) {
	if len(s) > 0 && s[len(s)-1] != '\n' { // We need a closing newline
		return ReadRR(strings.NewReader(s+"\n"), "")
	}
	return ReadRR(strings.NewReader(s), "")
}

// ReadRR reads the RR contained in r.
//
// The string file is used in error reporting and to resolve relative
// $INCLUDE directives.
//
// See NewRR for more documentation.
func ReadRR(r io.Reader, file string) (RR, error) {
	zp := NewZoneParser(r, mustParseName("."), file)
	zp.SetDefaultTTL(defaultTtl)
	zp.SetIncludeAllowed(true)
	rr, _ := zp.Next()
	return rr, zp.Err()
}

// ZoneParser is a parser for an RFC 1035 style zonefile.
//
// Each parsed RR in the zone is returned sequentially from Next. An
// optional comment can be retrieved with Comment.
//
// The directives $INCLUDE, $ORIGIN, $TTL and $GENERATE are all
// supported. Although $INCLUDE is disabled by default.
// Note that $GENERATE's range support up to a maximum of 65535 steps.
//
// Basic usage pattern when reading from a string (z) containing the
// zone data:
//
//	zp := NewZoneParser(strings.NewReader(z), "", "")
//
//	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
//		// Do something with rr
//	}
//
//	if err := zp.Err(); err != nil {
//		// log.Println(err)
//	}
//
// Comments specified after an RR (and on the same line!) are
// returned too:
//
//	foo. IN A 10.0.0.1 ; this is a comment
//
// The text "; this is comment" is returned from Comment. Comments inside
// the RR are returned concatenated along with the RR. Comments on a line
// by themselves are discarded.
//
// Callers should not assume all returned data in an Resource Record is
// syntactically correct, e.g. illegal base64 in RRSIGs will be returned as-is.
type ZoneParser struct {
	c *zlexer

	parseErr *ParseError

	origin Name
	file   string

	defttl *ttlState

	h RR_Header

	// sub is used to parse $INCLUDE files and $GENERATE directives.
	// Next, by calling subNext, forwards the resulting RRs from this
	// sub parser to the calling code.
	sub  *ZoneParser
	r    io.Reader
	fsys fs.FS

	includeDepth uint8

	includeAllowed     bool
	generateDisallowed bool
}

// NewZoneParser returns an RFC 1035 style zonefile parser that reads
// from r.
//
// The string file is used in error reporting and to resolve relative
// $INCLUDE directives. The string origin is used as the initial
// origin, as if the file would start with an $ORIGIN directive.
func NewZoneParser(r io.Reader, origin Name, file string) *ZoneParser {
	var pe *ParseError

	return &ZoneParser{
		c: newZLexer(r),

		parseErr: pe,

		origin: origin,
		file:   file,
	}
}

// SetDefaultTTL sets the parsers default TTL to ttl.
func (zp *ZoneParser) SetDefaultTTL(ttl uint32) {
	zp.defttl = &ttlState{ttl, false}
}

// SetIncludeAllowed controls whether $INCLUDE directives are
// allowed. $INCLUDE directives are not supported by default.
//
// The $INCLUDE directive will open and read from a user controlled
// file on the system. Even if the file is not a valid zonefile, the
// contents of the file may be revealed in error messages, such as:
//
//	/etc/passwd: dns: not a TTL: "root:x:0:0:root:/root:/bin/bash" at line: 1:31
//	/etc/shadow: dns: not a TTL: "root:$6$<redacted>::0:99999:7:::" at line: 1:125
func (zp *ZoneParser) SetIncludeAllowed(v bool) {
	zp.includeAllowed = v
}

// SetIncludeFS provides an [fs.FS] to use when looking for the target of
// $INCLUDE directives.  ($INCLUDE must still be enabled separately by calling
// [ZoneParser.SetIncludeAllowed].)  If fsys is nil, [os.Open] will be used.
//
// When fsys is an on-disk FS, the ability of $INCLUDE to reach files from
// outside its root directory depends upon the FS implementation.  For
// instance, [os.DirFS] will refuse to open paths like "../../etc/passwd",
// however it will still follow links which may point anywhere on the system.
//
// FS paths are slash-separated on all systems, even Windows.  $INCLUDE paths
// containing other characters such as backslash and colon may be accepted as
// valid, but those characters will never be interpreted by an FS
// implementation as path element separators.  See [fs.ValidPath] for more
// details.
func (zp *ZoneParser) SetIncludeFS(fsys fs.FS) {
	zp.fsys = fsys
}

// Err returns the first non-EOF error that was encountered by the
// ZoneParser.
func (zp *ZoneParser) Err() error {
	if zp.parseErr != nil {
		return zp.parseErr
	}

	if zp.sub != nil {
		if err := zp.sub.Err(); err != nil {
			return err
		}
	}

	return zp.c.Err()
}

func (zp *ZoneParser) setParseError(err string, l lex) (RR, bool) {
	zp.parseErr = &ParseError{file: zp.file, err: err, lex: l}
	return nil, false
}

// Comment returns an optional text comment that occurred alongside
// the RR.
func (zp *ZoneParser) Comment() string {
	if zp.parseErr != nil {
		return ""
	}

	if zp.sub != nil {
		return zp.sub.Comment()
	}

	return zp.c.Comment()
}

func (zp *ZoneParser) subNext() (RR, bool) {
	if rr, ok := zp.sub.Next(); ok {
		return rr, true
	}

	if zp.sub.r != nil {
		if c, ok := zp.sub.r.(io.Closer); ok {
			c.Close()
		}
		zp.sub.r = nil
	}

	if zp.sub.Err() != nil {
		// We have errors to surface.
		return nil, false
	}

	zp.sub = nil
	return zp.Next()
}

// Next advances the parser to the next RR in the zonefile and
// returns the (RR, true). It will return (nil, false) when the
// parsing stops, either by reaching the end of the input or an
// error. After Next returns (nil, false), the Err method will return
// any error that occurred during parsing.
func (zp *ZoneParser) Next() (RR, bool) {
	if zp.parseErr != nil {
		return nil, false
	}
	if zp.sub != nil {
		return zp.subNext()
	}

	// 6 possible beginnings of a line (_ is a space):
	//
	//   0. zRRTYPE                              -> all omitted until the rrtype
	//   1. zOwner _ zRrtype                     -> class/ttl omitted
	//   2. zOwner _ zString _ zRrtype           -> class omitted
	//   3. zOwner _ zString _ zClass  _ zRrtype -> ttl/class
	//   4. zOwner _ zClass  _ zRrtype           -> ttl omitted
	//   5. zOwner _ zClass  _ zString _ zRrtype -> class/ttl (reversed)
	//
	// After detecting these, we know the zRrtype so we can jump to functions
	// handling the rdata for each of these types.

	st := zExpectOwnerDir // initial state
	h := &zp.h

	for l, ok := zp.c.Next(); ok; l, ok = zp.c.Next() {
		// zlexer spotted an error already
		if l.err {
			return zp.setParseError(l.token, l)
		}

		switch st {
		case zExpectOwnerDir:
			// We can also expect a directive, like $TTL or $ORIGIN
			if zp.defttl != nil {
				h.Ttl = zp.defttl.ttl
			}

			h.Class = ClassINET

			switch l.value {
			case zNewline:
				st = zExpectOwnerDir
			case zOwner:
				name, ok := toAbsoluteName(l.token, zp.origin)
				if !ok {
					return zp.setParseError("bad owner name", l)
				}

				h.Name = name

				st = zExpectOwnerBl
			case zDirTTL:
				st = zExpectDirTTLBl
			case zDirOrigin:
				st = zExpectDirOriginBl
			case zDirInclude:
				st = zExpectDirIncludeBl
			case zDirGenerate:
				st = zExpectDirGenerateBl
			case zRrtpe:
				h.Rrtype = Type(l.torc)

				st = zExpectRdata
			case zClass:
				h.Class = Class(l.torc)

				st = zExpectAnyNoClassBl
			case zBlank:
				// Discard, can happen when there is nothing on the
				// line except the RR type
			case zString:
				ttl, ok := stringToTTL(l.token)
				if !ok {
					return zp.setParseError("not a TTL", l)
				}

				h.Ttl = ttl

				if zp.defttl == nil || !zp.defttl.isByDirective {
					zp.defttl = &ttlState{ttl, false}
				}

				st = zExpectAnyNoTTLBl
			default:
				return zp.setParseError("syntax error at beginning", l)
			}
		case zExpectDirIncludeBl:
			if l.value != zBlank {
				return zp.setParseError("no blank after $INCLUDE-directive", l)
			}

			st = zExpectDirInclude
		case zExpectDirInclude:
			if l.value != zString {
				return zp.setParseError("expecting $INCLUDE value, not this...", l)
			}

			neworigin := zp.origin // There may be optionally a new origin set after the filename, if not use current one
			switch l, _ := zp.c.Next(); l.value {
			case zBlank:
				l, _ := zp.c.Next()
				if l.value == zString {
					name, ok := toAbsoluteName(l.token, zp.origin)
					if !ok {
						return zp.setParseError("bad origin name", l)
					}

					neworigin = name
				}
			case zNewline, zEOF:
				// Ok
			default:
				return zp.setParseError("garbage after $INCLUDE", l)
			}

			if !zp.includeAllowed {
				return zp.setParseError("$INCLUDE directive not allowed", l)
			}
			if zp.includeDepth >= maxIncludeDepth {
				return zp.setParseError("too deeply nested $INCLUDE", l)
			}

			// Start with the new file
			includePath := l.token
			var r1 io.Reader
			var e1 error
			if zp.fsys != nil {
				// fs.FS always uses / as separator, even on Windows, so use
				// path instead of filepath here:
				if !path.IsAbs(includePath) {
					includePath = path.Join(path.Dir(zp.file), includePath)
				}

				// os.DirFS, and probably others, expect all paths to be
				// relative, so clean the path and remove leading / if
				// present:
				includePath = strings.TrimLeft(path.Clean(includePath), "/")

				r1, e1 = zp.fsys.Open(includePath)
			} else {
				if !filepath.IsAbs(includePath) {
					includePath = filepath.Join(filepath.Dir(zp.file), includePath)
				}
				r1, e1 = os.Open(includePath)
			}
			if e1 != nil {
				var as string
				if includePath != l.token {
					as = fmt.Sprintf(" as `%s'", includePath)
				}
				zp.parseErr = &ParseError{
					file:       zp.file,
					wrappedErr: fmt.Errorf("failed to open `%s'%s: %w", l.token, as, e1),
					lex:        l,
				}
				return nil, false
			}

			zp.sub = NewZoneParser(r1, neworigin, includePath)
			zp.sub.defttl, zp.sub.includeDepth, zp.sub.r = zp.defttl, zp.includeDepth+1, r1
			zp.sub.SetIncludeAllowed(true)
			zp.sub.SetIncludeFS(zp.fsys)
			return zp.subNext()
		case zExpectDirTTLBl:
			if l.value != zBlank {
				return zp.setParseError("no blank after $TTL-directive", l)
			}

			st = zExpectDirTTL
		case zExpectDirTTL:
			if l.value != zString {
				return zp.setParseError("expecting $TTL value, not this...", l)
			}

			if err := slurpRemainder(zp.c); err != nil {
				return zp.setParseError(err.err, err.lex)
			}

			ttl, ok := stringToTTL(l.token)
			if !ok {
				return zp.setParseError("expecting $TTL value, not this...", l)
			}

			zp.defttl = &ttlState{ttl, true}

			st = zExpectOwnerDir
		case zExpectDirOriginBl:
			if l.value != zBlank {
				return zp.setParseError("no blank after $ORIGIN-directive", l)
			}

			st = zExpectDirOrigin
		case zExpectDirOrigin:
			if l.value != zString {
				return zp.setParseError("expecting $ORIGIN value, not this...", l)
			}

			if err := slurpRemainder(zp.c); err != nil {
				return zp.setParseError(err.err, err.lex)
			}

			name, ok := toAbsoluteName(l.token, zp.origin)
			if !ok {
				return zp.setParseError("bad origin name", l)
			}

			zp.origin = name

			st = zExpectOwnerDir
		case zExpectDirGenerateBl:
			if l.value != zBlank {
				return zp.setParseError("no blank after $GENERATE-directive", l)
			}

			st = zExpectDirGenerate
		case zExpectDirGenerate:
			if zp.generateDisallowed {
				return zp.setParseError("nested $GENERATE directive not allowed", l)
			}
			if l.value != zString {
				return zp.setParseError("expecting $GENERATE value, not this...", l)
			}

			return zp.generate(l)
		case zExpectOwnerBl:
			if l.value != zBlank {
				return zp.setParseError("no blank after owner", l)
			}

			st = zExpectAny
		case zExpectAny:
			switch l.value {
			case zRrtpe:
				if zp.defttl == nil {
					return zp.setParseError("missing TTL with no previous value", l)
				}

				h.Rrtype = Type(l.torc)

				st = zExpectRdata
			case zClass:
				h.Class = Class(l.torc)

				st = zExpectAnyNoClassBl
			case zString:
				ttl, ok := stringToTTL(l.token)
				if !ok {
					return zp.setParseError("not a TTL", l)
				}

				h.Ttl = ttl

				if zp.defttl == nil || !zp.defttl.isByDirective {
					zp.defttl = &ttlState{ttl, false}
				}

				st = zExpectAnyNoTTLBl
			default:
				return zp.setParseError("expecting RR type, TTL or class, not this...", l)
			}
		case zExpectAnyNoClassBl:
			if l.value != zBlank {
				return zp.setParseError("no blank before class", l)
			}

			st = zExpectAnyNoClass
		case zExpectAnyNoTTLBl:
			if l.value != zBlank {
				return zp.setParseError("no blank before TTL", l)
			}

			st = zExpectAnyNoTTL
		case zExpectAnyNoTTL:
			switch l.value {
			case zClass:
				h.Class = Class(l.torc)

				st = zExpectRrtypeBl
			case zRrtpe:
				h.Rrtype = Type(l.torc)

				st = zExpectRdata
			default:
				return zp.setParseError("expecting RR type or class, not this...", l)
			}
		case zExpectAnyNoClass:
			switch l.value {
			case zString:
				ttl, ok := stringToTTL(l.token)
				if !ok {
					return zp.setParseError("not a TTL", l)
				}

				h.Ttl = ttl

				if zp.defttl == nil || !zp.defttl.isByDirective {
					zp.defttl = &ttlState{ttl, false}
				}

				st = zExpectRrtypeBl
			case zRrtpe:
				h.Rrtype = Type(l.torc)

				st = zExpectRdata
			default:
				return zp.setParseError("expecting RR type or TTL, not this...", l)
			}
		case zExpectRrtypeBl:
			if l.value != zBlank {
				return zp.setParseError("no blank before RR type", l)
			}

			st = zExpectRrtype
		case zExpectRrtype:
			if l.value != zRrtpe {
				return zp.setParseError("unknown RR type", l)
			}

			h.Rrtype = Type(l.torc)

			st = zExpectRdata
		case zExpectRdata:
			var (
				rr             RR
				parseAsRFC3597 bool
			)
			if newFn, ok := TypeToRR[h.Rrtype]; ok {
				rr = newFn()
				*rr.Header() = *h

				// We may be parsing a known RR type using the RFC3597 format.
				// If so, we handle that here in a generic way.
				//
				// This is also true for PrivateRR types which will have the
				// RFC3597 parsing done for them and the Unpack method called
				// to populate the RR instead of simply deferring to Parse.
				if zp.c.Peek().token == "\\#" {
					parseAsRFC3597 = true
				}
			} else {
				rr = &RFC3597{Hdr: *h}
			}

			_, isPrivate := rr.(*PrivateRR)
			if !isPrivate && zp.c.Peek().token == "" {
				// This is a dynamic update rr.

				if err := slurpRemainder(zp.c); err != nil {
					return zp.setParseError(err.err, err.lex)
				}

				return rr, true
			} else if l.value == zNewline {
				return zp.setParseError("unexpected newline", l)
			}

			parseAsRR := rr
			if parseAsRFC3597 {
				parseAsRR = &RFC3597{Hdr: *h}
			}

			if err := parseAsRR.parse(zp.c, zp.origin); err != nil {
				// err is a concrete *ParseError without the file field set.
				// The setParseError call below will construct a new
				// *ParseError with file set to zp.file.

				// err.lex may be nil in which case we substitute our current
				// lex token.
				if err.lex == (lex{}) {
					return zp.setParseError(err.err, l)
				}

				return zp.setParseError(err.err, err.lex)
			}

			if parseAsRFC3597 {
				err := parseAsRR.(*RFC3597).fromRFC3597(rr)
				if err != nil {
					return zp.setParseError(err.Error(), l)
				}
			}

			return rr, true
		}
	}

	// If we get here, we and the h.Rrtype is still zero, we haven't parsed anything, this
	// is not an error, because an empty zone file is still a zone file.
	return nil, false
}

type zlexer struct {
	br io.ByteReader

	readErr error

	line   int
	column int

	comBuf  string
	comment string

	l       lex
	cachedL *lex

	brace  int
	quote  bool
	space  bool
	commt  bool
	rrtype bool
	owner  bool

	nextL bool

	eol bool // end-of-line
}

func newZLexer(r io.Reader) *zlexer {
	br, ok := r.(io.ByteReader)
	if !ok {
		br = bufio.NewReaderSize(r, 1024)
	}

	return &zlexer{
		br: br,

		line: 1,

		owner: true,
	}
}

func (zl *zlexer) Err() error {
	if zl.readErr == io.EOF {
		return nil
	}

	return zl.readErr
}

// readByte returns the next byte from the input
func (zl *zlexer) readByte() (byte, bool) {
	if zl.readErr != nil {
		return 0, false
	}

	c, err := zl.br.ReadByte()
	if err != nil {
		zl.readErr = err
		return 0, false
	}

	// delay the newline handling until the next token is delivered,
	// fixes off-by-one errors when reporting a parse error.
	if zl.eol {
		zl.line++
		zl.column = 0
		zl.eol = false
	}

	if c == '\n' {
		zl.eol = true
	} else {
		zl.column++
	}

	return c, true
}

func (zl *zlexer) Peek() lex {
	if zl.nextL {
		return zl.l
	}

	l, ok := zl.Next()
	if !ok {
		return l
	}

	if zl.nextL {
		// Cache l. Next returns zl.cachedL then zl.l.
		zl.cachedL = &l
	} else {
		// In this case l == zl.l, so we just tell Next to return zl.l.
		zl.nextL = true
	}

	return l
}

func (zl *zlexer) Next() (lex, bool) {
	l := &zl.l
	switch {
	case zl.cachedL != nil:
		l, zl.cachedL = zl.cachedL, nil
		return *l, true
	case zl.nextL:
		zl.nextL = false
		return *l, true
	case l.err:
		// Parsing errors should be sticky.
		return lex{value: zEOF}, false
	}

	var (
		str = make([]byte, maxTok) // Hold string text
		com = make([]byte, maxTok) // Hold comment text

		stri int // Offset in str (0 means empty)
		comi int // Offset in com (0 means empty)

		escape bool
	)

	if zl.comBuf != "" {
		comi = copy(com[:], zl.comBuf)
		zl.comBuf = ""
	}

	zl.comment = ""

	for x, ok := zl.readByte(); ok; x, ok = zl.readByte() {
		l.line, l.column = zl.line, zl.column

		if stri >= len(str) {
			// if buffer length is insufficient, increase it.
			str = append(str[:], make([]byte, maxTok)...)
		}
		if comi >= len(com) {
			// if buffer length is insufficient, increase it.
			com = append(com[:], make([]byte, maxTok)...)
		}

		switch x {
		case ' ', '\t':
			if escape || zl.quote {
				// Inside quotes or escaped this is legal.
				str[stri] = x
				stri++

				escape = false
				break
			}

			if zl.commt {
				com[comi] = x
				comi++
				break
			}

			var retL lex
			if stri == 0 {
				// Space directly in the beginning, handled in the grammar
			} else if zl.owner {
				// If we have a string and it's the first, make it an owner
				l.value = zOwner
				l.token = string(str[:stri])

				// escape $... start with a \ not a $, so this will work
				switch strings.ToUpper(l.token) {
				case "$TTL":
					l.value = zDirTTL
				case "$ORIGIN":
					l.value = zDirOrigin
				case "$INCLUDE":
					l.value = zDirInclude
				case "$GENERATE":
					l.value = zDirGenerate
				}

				retL = *l
			} else {
				l.value = zString
				l.token = string(str[:stri])

				if !zl.rrtype {
					tokenUpper := strings.ToUpper(l.token)
					if t, ok := StringToType[tokenUpper]; ok {
						l.value = zRrtpe
						l.torc = uint16(t)

						zl.rrtype = true
					} else if strings.HasPrefix(tokenUpper, "TYPE") {
						t, ok := typeToInt(l.token)
						if !ok {
							l.token = "unknown RR type"
							l.err = true
							return *l, true
						}

						l.value = zRrtpe
						l.torc = t

						zl.rrtype = true
					}

					if t, ok := StringToClass[tokenUpper]; ok {
						l.value = zClass
						l.torc = uint16(t)
					} else if strings.HasPrefix(tokenUpper, "CLASS") {
						t, ok := classToInt(l.token)
						if !ok {
							l.token = "unknown class"
							l.err = true
							return *l, true
						}

						l.value = zClass
						l.torc = t
					}
				}

				retL = *l
			}

			zl.owner = false

			if !zl.space {
				zl.space = true

				l.value = zBlank
				l.token = " "

				if retL == (lex{}) {
					return *l, true
				}

				zl.nextL = true
			}

			if retL != (lex{}) {
				return retL, true
			}
		case ';':
			if escape || zl.quote {
				// Inside quotes or escaped this is legal.
				str[stri] = x
				stri++

				escape = false
				break
			}

			zl.commt = true
			zl.comBuf = ""

			if comi > 1 {
				// A newline was previously seen inside a comment that
				// was inside braces and we delayed adding it until now.
				com[comi] = ' ' // convert newline to space
				comi++
				if comi >= len(com) {
					l.token = "comment length insufficient for parsing"
					l.err = true
					return *l, true
				}
			}

			com[comi] = ';'
			comi++

			if stri > 0 {
				zl.comBuf = string(com[:comi])

				l.value = zString
				l.token = string(str[:stri])
				return *l, true
			}
		case '\r':
			escape = false

			if zl.quote {
				str[stri] = x
				stri++
			}

			// discard if outside of quotes
		case '\n':
			escape = false

			// Escaped newline
			if zl.quote {
				str[stri] = x
				stri++
				break
			}

			if zl.commt {
				// Reset a comment
				zl.commt = false
				zl.rrtype = false

				// If not in a brace this ends the comment AND the RR
				if zl.brace == 0 {
					zl.owner = true

					l.value = zNewline
					l.token = "\n"
					zl.comment = string(com[:comi])
					return *l, true
				}

				zl.comBuf = string(com[:comi])
				break
			}

			if zl.brace == 0 {
				// If there is previous text, we should output it here
				var retL lex
				if stri != 0 {
					l.value = zString
					l.token = string(str[:stri])

					if !zl.rrtype {
						tokenUpper := strings.ToUpper(l.token)
						if t, ok := StringToType[tokenUpper]; ok {
							zl.rrtype = true

							l.value = zRrtpe
							l.torc = uint16(t)
						}
					}

					retL = *l
				}

				l.value = zNewline
				l.token = "\n"

				zl.comment = zl.comBuf
				zl.comBuf = ""
				zl.rrtype = false
				zl.owner = true

				if retL != (lex{}) {
					zl.nextL = true
					return retL, true
				}

				return *l, true
			}
		case '\\':
			// comments do not get escaped chars, everything is copied
			if zl.commt {
				com[comi] = x
				comi++
				break
			}

			// something already escaped must be in string
			if escape {
				str[stri] = x
				stri++

				escape = false
				break
			}

			// something escaped outside of string gets added to string
			str[stri] = x
			stri++

			escape = true
		case '"':
			if zl.commt {
				com[comi] = x
				comi++
				break
			}

			if escape {
				str[stri] = x
				stri++

				escape = false
				break
			}

			zl.space = false

			// send previous gathered text and the quote
			var retL lex
			if stri != 0 {
				l.value = zString
				l.token = string(str[:stri])

				retL = *l
			}

			// send quote itself as separate token
			l.value = zQuote
			l.token = "\""

			zl.quote = !zl.quote

			if retL != (lex{}) {
				zl.nextL = true
				return retL, true
			}

			return *l, true
		case '(', ')':
			if zl.commt {
				com[comi] = x
				comi++
				break
			}

			if escape || zl.quote {
				// Inside quotes or escaped this is legal.
				str[stri] = x
				stri++

				escape = false
				break
			}

			switch x {
			case ')':
				zl.brace--

				if zl.brace < 0 {
					l.token = "extra closing brace"
					l.err = true
					return *l, true
				}
			case '(':
				zl.brace++
			}
		default:
			escape = false

			if zl.commt {
				com[comi] = x
				comi++
				break
			}

			str[stri] = x
			stri++

			zl.space = false
		}
	}

	if zl.readErr != nil && zl.readErr != io.EOF {
		// Don't return any tokens after a read error occurs.
		return lex{value: zEOF}, false
	}

	var retL lex
	if stri > 0 {
		// Send remainder of str
		l.value = zString
		l.token = string(str[:stri])
		retL = *l

		if comi <= 0 {
			return retL, true
		}
	}

	if comi > 0 {
		// Send remainder of com
		l.value = zNewline
		l.token = "\n"
		zl.comment = string(com[:comi])

		if retL != (lex{}) {
			zl.nextL = true
			return retL, true
		}

		return *l, true
	}

	if zl.brace != 0 {
		l.token = "unbalanced brace"
		l.err = true
		return *l, true
	}

	return lex{value: zEOF}, false
}

func (zl *zlexer) Comment() string {
	if zl.l.err {
		return ""
	}

	return zl.comment
}

// Extract the class number from CLASSxx
func classToInt(token string) (uint16, bool) {
	offset := 5
	if len(token) < offset+1 {
		return 0, false
	}
	class, err := strconv.ParseUint(token[offset:], 10, 16)
	if err != nil {
		return 0, false
	}
	return uint16(class), true
}

// Extract the rr number from TYPExxx
func typeToInt(token string) (uint16, bool) {
	offset := 4
	if len(token) < offset+1 {
		return 0, false
	}
	typ, err := strconv.ParseUint(token[offset:], 10, 16)
	if err != nil {
		return 0, false
	}
	return uint16(typ), true
}

// stringToTTL parses things like 2w, 2m, etc, and returns the time in seconds.
func stringToTTL(token string) (uint32, bool) {
	var s, i uint32
	for _, c := range token {
		switch c {
		case 's', 'S':
			s += i
			i = 0
		case 'm', 'M':
			s += i * 60
			i = 0
		case 'h', 'H':
			s += i * 60 * 60
			i = 0
		case 'd', 'D':
			s += i * 60 * 60 * 24
			i = 0
		case 'w', 'W':
			s += i * 60 * 60 * 24 * 7
			i = 0
		case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
			i *= 10
			i += uint32(c) - '0'
		default:
			return 0, false
		}
	}
	return s + i, true
}

// Parse LOC records' <digits>[.<digits>][mM] into a
// mantissa exponent format. Token should contain the entire
// string (i.e. no spaces allowed)
func stringToCm(token string) (e, m uint8, ok bool) {
	if token[len(token)-1] == 'M' || token[len(token)-1] == 'm' {
		token = token[0 : len(token)-1]
	}

	var (
		meters, cmeters, val int
		err                  error
	)
	mStr, cmStr, hasCM := strings.Cut(token, ".")
	if hasCM {
		// There's no point in having more than 2 digits in this part, and would rather make the implementation complicated ('123' should be treated as '12').
		// So we simply reject it.
		// We also make sure the first character is a digit to reject '+-' signs.
		cmeters, err = strconv.Atoi(cmStr)
		if err != nil || len(cmStr) > 2 || cmStr[0] < '0' || cmStr[0] > '9' {
			return
		}
		if len(cmStr) == 1 {
			// 'nn.1' must be treated as 'nn-meters and 10cm, not 1cm.
			cmeters *= 10
		}
	}
	// This slightly ugly condition will allow omitting the 'meter' part, like .01 (meaning 0.01m = 1cm).
	if !hasCM || mStr != "" {
		meters, err = strconv.Atoi(mStr)
		// RFC1876 states the max value is 90000000.00.  The latter two conditions enforce it.
		if err != nil || mStr[0] < '0' || mStr[0] > '9' || meters > 90000000 || (meters == 90000000 && cmeters != 0) {
			return
		}
	}

	if meters > 0 {
		e = 2
		val = meters
	} else {
		e = 0
		val = cmeters
	}
	for val >= 10 {
		e++
		val /= 10
	}
	return e, uint8(val), true
}

func toAbsoluteName(name string, origin Name) (absolute Name, ok bool) {
	// check for an explicit origin reference
	if name == "@" {
		// require a nonempty origin
		if origin.EncodedLen() == 0 {
			return absolute, false
		}
		return origin, true
	}

	// this can happen when we have a comment after a RR that has a domain, '...   MX 20 ; this is wrong'.
	// technically a newline can be in a domain name, but this is clearly an error and the newline only shows
	// because of the scanning and the comment.
	if name == "\n" {
		return absolute, false
	}

	// require a valid domain name
	_, ok = IsDomainName(name)
	if !ok || name == "" {
		return absolute, false
	}

	// check if name is already absolute
	if IsFqdn(name) {
		absolute, err := NameFromString(name)
		return absolute, err == nil
	}

	// require a nonempty origin
	if origin.EncodedLen() == 0 {
		return absolute, false
	}
	absolute, err := appendOrigin(name, origin)
	return absolute, err == nil
}

func appendOrigin(name string, origin Name) (Name, error) {
	originS := origin.String()
	if originS == "." {
		return NameFromString(name + ".")
	}
	return NameFromString(name + "." + originS)
}

// LOC record helper function
func locCheckNorth(token string, latitude uint32) (uint32, bool) {
	if latitude > 90*1000*60*60 {
		return latitude, false
	}
	switch token {
	case "n", "N":
		return LOC_EQUATOR + latitude, true
	case "s", "S":
		return LOC_EQUATOR - latitude, true
	}
	return latitude, false
}

// LOC record helper function
func locCheckEast(token string, longitude uint32) (uint32, bool) {
	if longitude > 180*1000*60*60 {
		return longitude, false
	}
	switch token {
	case "e", "E":
		return LOC_EQUATOR + longitude, true
	case "w", "W":
		return LOC_EQUATOR - longitude, true
	}
	return longitude, false
}

// "Eat" the rest of the "line"
func slurpRemainder(c *zlexer) *ParseError {
	l, _ := c.Next()
	switch l.value {
	case zBlank:
		l, _ = c.Next()
		if l.value != zNewline && l.value != zEOF {
			return &ParseError{err: "garbage after rdata", lex: l}
		}
	case zNewline:
	case zEOF:
	default:
		return &ParseError{err: "garbage after rdata", lex: l}
	}
	return nil
}

// Parse a 64 bit-like ipv6 address: "0014:4fff:ff20:ee64"
// Used for NID and L64 record.
func stringToNodeID(l lex) (uint64, *ParseError) {
	if len(l.token) < 19 {
		return 0, &ParseError{file: l.token, err: "bad NID/L64 NodeID/Locator64", lex: l}
	}
	// There must be three colons at fixes positions, if not its a parse error
	if l.token[4] != ':' && l.token[9] != ':' && l.token[14] != ':' {
		return 0, &ParseError{file: l.token, err: "bad NID/L64 NodeID/Locator64", lex: l}
	}
	s := l.token[0:4] + l.token[5:9] + l.token[10:14] + l.token[15:19]
	u, err := strconv.ParseUint(s, 16, 64)
	if err != nil {
		return 0, &ParseError{file: l.token, err: "bad NID/L64 NodeID/Locator64", lex: l}
	}
	return u, nil
}
