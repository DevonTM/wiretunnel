package wiretunnel

import (
	"fmt"
	"math/rand/v2"
	"net"
	"strings"

	"github.com/txthinking/socks5"
)

func (s *SOCKS5Server) udpHandle(ss *socks5.Server, addr *net.UDPAddr, d *socks5.Datagram) error {
	src := addr.String()
	dst := d.Address()

	var ue *socks5.UDPExchange
	any, ok := ss.UDPExchanges.Get(src + dst)
	if ok {
		ue = any.(*socks5.UDPExchange)
		return exchangeUDP(ue, d.Data)
	}

	var laddr string
	any, ok = ss.UDPSrc.Get(src + dst)
	if ok {
		laddr = any.(string)
	}

	rc, err := s.dialUDP(laddr, dst)
	if err != nil {
		if !strings.Contains(err.Error(), "port is in use") {
			return err
		}
		rc, err = s.dialUDP("", dst)
		if err != nil {
			return err
		}
		laddr = ""
	}
	if laddr == "" {
		ss.UDPSrc.Set(src+dst, rc.LocalAddr().String(), -1)
	}

	ue = &socks5.UDPExchange{
		ClientAddr: addr,
		RemoteConn: rc,
	}
	err = exchangeUDP(ue, d.Data)
	if err != nil {
		ue.RemoteConn.Close()
		return err
	}
	ss.UDPExchanges.Set(src+dst, ue, -1)

	go func(ue *socks5.UDPExchange, dst string) {
		defer func() {
			ue.RemoteConn.Close()
			ss.UDPExchanges.Delete(ue.ClientAddr.String() + dst)
		}()
		b := make([]byte, 65507)
		for {
			n, err := ue.RemoteConn.Read(b)
			if err != nil {
				return
			}
			a, addr, port, err := socks5.ParseAddress(dst)
			if err != nil {
				return
			}
			if a == socks5.ATYPDomain {
				addr = addr[1:]
			}
			d := socks5.NewDatagram(a, addr, port, b[:n])
			_, err = ss.UDPConn.WriteToUDP(d.Bytes(), ue.ClientAddr)
			if err != nil {
				return
			}
		}
	}(ue, dst)
	return nil
}

func exchangeUDP(ue *socks5.UDPExchange, data []byte) error {
	_, err := ue.RemoteConn.Write(data)
	if err != nil {
		return err
	}
	return nil
}

func (s *SOCKS5Server) dialUDP(src, dst string) (net.Conn, error) {
	laddr, err := net.ResolveUDPAddr("udp", src)
	if err != nil {
		return nil, fmt.Errorf("Dial: %w", err)
	}

	host, port, err := net.SplitHostPort(dst)
	if err != nil {
		return nil, fmt.Errorf("Dial: %w", err)
	}

	addrs, err := s.lookup(host)
	if err != nil {
		return nil, fmt.Errorf("Dial: %w", err)
	}

	host = addrs[rand.IntN(len(addrs))]
	dst = net.JoinHostPort(host, port)
	raddr, err := net.ResolveUDPAddr("udp", dst)
	if err != nil {
		return nil, fmt.Errorf("Dial: %w", err)
	}

	if raddr.IP.IsLoopback() || raddr.IP.IsUnspecified() {
		return nil, fmt.Errorf("Dial: invalid address %s", dst)
	}

	for _, bypass := range s.BypassList {
		if bypass.Contains(raddr.IP) {
			return net.DialUDP("udp", laddr, raddr)
		}
	}

	return s.Dialer.DialUDP(laddr, raddr)
}
