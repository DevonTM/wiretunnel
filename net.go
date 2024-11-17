package wiretunnel

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/botanica-consulting/wiredialer"
)

// NewDialer returns a new wiredialer.WireDialer from a WireGuard configuration file.
func NewDialer(path string) (*wiredialer.WireDialer, error) {
	return wiredialer.NewDialerFromFile(path)
}

type dialFunc func(ctx context.Context, network string, address string) (net.Conn, error)

// dialWithResolver returns a dial function that resolves the address with the given resolver.
func dialWithResolver(dial dialFunc, r Resolver) dialFunc {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		startTime := time.Now()

		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, fmt.Errorf("Dial: %w", err)
		}

		addrs, err := r.LookupHost(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("Dial: %w", err)
		}

		// dynamically adjust the timeout based on the number of addresses
		min := 2 * time.Second
		max := 10 * time.Second
		timeout := max / time.Duration(len(addrs))
		if timeout < min {
			timeout = min
		}

		var errorMessages []string

		for _, addr := range addrs {
			ctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			target := net.JoinHostPort(addr, port)
			conn, err := dial(ctx, network, target)
			if err == nil {
				return conn, nil
			} else if err == context.Canceled {
				return nil, fmt.Errorf("Dial: canceled when dialing %s after %.3f seconds", address, time.Since(startTime).Seconds())
			} else if err == context.DeadlineExceeded {
				err = fmt.Errorf("Dial: timed out when dialing %s", target)
			}
			errorMessages = append(errorMessages, err.Error())
			cancel()
		}

		return nil, fmt.Errorf("Dial: failed when dialing %s after %.3f seconds. Reasons: %s", address, time.Since(startTime).Seconds(), strings.Join(errorMessages, "; "))
	}
}

// dialFilter returns a dial function that filters out loopback and unspecified addresses.
func dialFilter(dial dialFunc, bypassList []*net.IPNet) dialFunc {
	netDialer := new(net.Dialer)
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return nil, fmt.Errorf("Dial: %w", err)
		}

		ip := net.ParseIP(host)
		if ip.IsLoopback() || ip.IsUnspecified() {
			return nil, fmt.Errorf("Dial: invalid address %s", address)
		}

		for _, bypass := range bypassList {
			if bypass.Contains(ip) {
				return netDialer.DialContext(ctx, network, address)
			}
		}

		return dial(ctx, network, address)
	}
}
