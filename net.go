package wiretunnel

import (
	"context"
	"fmt"
	"net"

	"github.com/DevonTM/wiretunnel/resolver"
	"github.com/botanica-consulting/wiredialer"
)

// NewDialer returns a new wiredialer.WireDialer from a WireGuard configuration file.
func NewDialer(path string) (*wiredialer.WireDialer, error) {
	return wiredialer.NewDialerFromFile(path)
}

// dialWithLocalDNS returns a dial function that uses a local DNS resolver to resolve the hostname before dialing.
func dialWithLocalDNS(r *resolver.Resolver, d *wiredialer.WireDialer) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, fmt.Errorf("dial: %w", err)
		}

		addrs, err := r.LookupHost(host)
		if err != nil {
			return nil, fmt.Errorf("dial: %w", err)
		}

		for _, addr := range addrs {
			conn, err := d.DialContext(ctx, network, net.JoinHostPort(addr, port))
			if err == nil {
				return conn, nil
			}
		}

		return nil, fmt.Errorf("dial: failed to dial %s", address)
	}
}
