package wiretunnel

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/DevonTM/wiretunnel/resolver"
	"github.com/botanica-consulting/wiredialer"
)

// NewDialer returns a new wiredialer.WireDialer from a WireGuard configuration file.
func NewDialer(path string) (*wiredialer.WireDialer, error) {
	return wiredialer.NewDialerFromFile(path)
}

type dialFunc func(ctx context.Context, network string, address string) (net.Conn, error)

// dialWithResolver returns a dial function that resolves the address with the given resolver.
func dialWithResolver(dial dialFunc, r *resolver.Resolver) dialFunc {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, fmt.Errorf("dial: %w", err)
		}

		addrs, err := r.LookupHost(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("dial: %w", err)
		}

		// dynamically adjust the timeout based on the number of addresses
		min := 2 * time.Second
		max := 10 * time.Second
		timeout := max / time.Duration(len(addrs))
		if timeout < min {
			timeout = min
		}

		for _, addr := range addrs {
			ctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			conn, err := dial(ctx, network, net.JoinHostPort(addr, port))
			if err == nil {
				return conn, nil
			}
			if err == context.Canceled {
				return nil, fmt.Errorf("dial: %w", err)
			}
			cancel()
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
