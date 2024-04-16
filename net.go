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

type dialFunc func(context.Context, string, string) (net.Conn, error)

// dialWithResolver returns a dial function that resolves the address with the given resolver.
func dialWithResolver(dial dialFunc, r *resolver.Resolver) dialFunc {
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
			conn, err := dial(ctx, network, net.JoinHostPort(addr, port))
			if err == nil {
				return conn, nil
			}
		}

		return nil, fmt.Errorf("dial: failed to dial %s", address)
	}
}

// dialFilter returns a dial function that filters out loopback and unspecified addresses.
func dialFilter(dial dialFunc) dialFunc {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return nil, fmt.Errorf("dial: %w", err)
		}
		ip := net.ParseIP(host)
		if ip.IsLoopback() || ip.IsUnspecified() {
			return nil, fmt.Errorf("dial: invalid address %s", address)
		}
		return dial(ctx, network, address)
	}
}
