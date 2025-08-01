//go:build windows || darwin

// TODO(tmthrgd): Remove this Windows-specific code if go.dev/issue/7175 and
//   go.dev/issue/7174 are ever fixed.

// NOTICE(stek29): darwin supports PKTINFO in sendmsg, but it unbinds sockets, see https://github.com/miekg/dns/issues/724

package dns

import (
	"net"
	"net/netip"
)

// SessionUDP holds the remote address
type SessionUDP struct {
	raddr *net.UDPAddr
}

// RemoteAddr returns the remote network address.
func (s *SessionUDP) RemoteAddr() net.Addr { return s.raddr }

// ReadFromSessionUDP acts just like net.UDPConn.ReadFrom(), but returns a session object instead of a
// net.UDPAddr.
func ReadFromSessionUDP(conn *net.UDPConn, b []byte) (int, *SessionUDP, error) {
	n, raddr, err := conn.ReadFrom(b)
	if err != nil {
		return n, nil, err
	}
	return n, &SessionUDP{raddr.(*net.UDPAddr)}, err
}

// WriteToSessionUDP acts just like net.UDPConn.WriteTo(), but uses a *SessionUDP instead of a net.Addr.
func WriteToSessionUDP(conn *net.UDPConn, b []byte, session *SessionUDP) (int, error) {
	return conn.WriteTo(b, session.raddr)
}

func setUDPSocketOptions(*net.UDPConn) error { return nil }
func parseDstFromOOB([]byte) netip.Addr      { return netip.Addr{} }
