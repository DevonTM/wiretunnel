package wiretunnel

import (
	"context"
	"errors"
	"log"
	"net"

	"github.com/botanica-consulting/wiredialer"
	"github.com/txthinking/runnergroup"
	"github.com/txthinking/socks5"
)

type SOCKS5Server struct {
	Address  string
	Username string
	Password string

	EnableLog bool

	Dialer     *wiredialer.WireDialer
	BypassList []*net.IPNet
	Resolver   Resolver

	dial   dialFunc
	lookup func(host string) ([]string, error)
}

// ListenAndServe listens on the s.Address and serves SOCKS5 requests.
func (s *SOCKS5Server) ListenAndServe() error {
	s.dial = dialFilter(s.Dialer.DialContext, s.BypassList)
	s.lookup = s.Dialer.LookupHost
	if s.Resolver != nil {
		s.dial = dialWithResolver(s.dial, s.Resolver)
		s.lookup = func(host string) ([]string, error) {
			return s.Resolver.LookupHost(context.Background(), host)
		}
	}

	if s.Username != "" && s.Password == "" {
		return errors.New("username is set but password is empty")
	}

	server, err := socks5.NewClassicServer(s.Address, "", s.Username, s.Password, 0, 0)
	if err != nil {
		return err
	}

	return s.listenAndServe(server)
}

func (s *SOCKS5Server) listenAndServe(ss *socks5.Server) error {
	tcpAddr, err := net.ResolveTCPAddr("tcp", ss.Addr)
	if err != nil {
		return err
	}
	l, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		return err
	}

	ss.RunnerGroup.Add(&runnergroup.Runner{
		Start: func() error {
			for {
				c, err := l.AcceptTCP()
				if err != nil {
					return err
				}
				go func(c *net.TCPConn) {
					defer c.Close()
					err := ss.Negotiate(c)
					if err != nil {
						return
					}
					r, err := ss.GetRequest(c)
					if err != nil {
						return
					}
					err = s.tcpHandle(c, r)
					if s.EnableLog && err != nil {
						log.Printf("SOCKS5 proxy server: TCP: %s: ERROR: %v", c.RemoteAddr(), err)
					}
				}(c)
			}
		},
		Stop: func() error {
			return l.Close()
		},
	})

	udpAddr, err := net.ResolveUDPAddr("udp", ss.Addr)
	if err != nil {
		l.Close()
		return err
	}
	ss.UDPConn, err = net.ListenUDP("udp", udpAddr)
	if err != nil {
		l.Close()
		return err
	}

	ss.RunnerGroup.Add(&runnergroup.Runner{
		Start: func() error {
			for {
				b := make([]byte, 65507)
				n, addr, err := ss.UDPConn.ReadFromUDP(b)
				if err != nil {
					return err
				}
				go func(addr *net.UDPAddr, b []byte) {
					d, err := socks5.NewDatagramFromBytes(b)
					if err != nil {
						return
					}
					if d.Frag != 0x00 {
						return
					}
					err = s.udpHandle(ss, addr, d)
					if s.EnableLog && err != nil {
						log.Printf("SOCKS5 proxy server: UDP: %s: ERROR: %v", addr, err)
					}
				}(addr, b[:n])
			}
		},
		Stop: func() error {
			return ss.UDPConn.Close()
		},
	})

	return ss.RunnerGroup.Wait()
}
