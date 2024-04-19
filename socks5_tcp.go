package wiretunnel

import (
	"context"
	"io"
	"net"

	"github.com/txthinking/socks5"
)

func (s *SOCKS5Server) tcpHandle(c *net.TCPConn, r *socks5.Request) error {
	if r.Cmd == socks5.CmdConnect {
		rc, err := s.connect(r, c)
		if err != nil {
			return err
		}
		defer rc.Close()

		go func() {
			b := make([]byte, 4096)
			for {
				n, err := rc.Read(b)
				if err != nil {
					return
				}
				_, err = c.Write(b[:n])
				if err != nil {
					return
				}
			}
		}()

		b := make([]byte, 4096)
		for {
			n, err := c.Read(b)
			if err != nil {
				return nil
			}
			_, err = rc.Write(b[:n])
			if err != nil {
				return nil
			}
		}
	}

	if r.Cmd == socks5.CmdUDP {
		_, err := r.UDP(c, c.LocalAddr())
		if err != nil {
			return err
		}
		io.Copy(io.Discard, c)
		return nil
	}

	return socks5.ErrUnsupportCmd
}

func (s *SOCKS5Server) connect(r *socks5.Request, w io.Writer) (net.Conn, error) {
	var p *socks5.Reply
	rc, err := s.dial(context.Background(), "tcp", r.Address())
	if err != nil {
		if r.Atyp == socks5.ATYPIPv4 || r.Atyp == socks5.ATYPDomain {
			p = socks5.NewReply(socks5.RepHostUnreachable, socks5.ATYPIPv4, []byte(net.IPv4zero), []byte{0x00, 0x00})
		} else {
			p = socks5.NewReply(socks5.RepHostUnreachable, socks5.ATYPIPv6, []byte(net.IPv6zero), []byte{0x00, 0x00})
		}
		if _, err := p.WriteTo(w); err != nil {
			return nil, err
		}
		return nil, err
	}

	a, addr, port, err := socks5.ParseAddress(rc.LocalAddr().String())
	if err != nil {
		rc.Close()
		if r.Atyp == socks5.ATYPIPv4 || r.Atyp == socks5.ATYPDomain {
			p = socks5.NewReply(socks5.RepHostUnreachable, socks5.ATYPIPv4, []byte(net.IPv4zero), []byte{0x00, 0x00})
		} else {
			p = socks5.NewReply(socks5.RepHostUnreachable, socks5.ATYPIPv6, []byte(net.IPv6zero), []byte{0x00, 0x00})
		}
		if _, err := p.WriteTo(w); err != nil {
			return nil, err
		}
		return nil, err
	}

	if a == socks5.ATYPDomain {
		addr = addr[1:]
	}

	p = socks5.NewReply(socks5.RepSuccess, a, addr, port)
	_, err = p.WriteTo(w)
	if err != nil {
		rc.Close()
		return nil, err
	}

	return rc, nil
}
