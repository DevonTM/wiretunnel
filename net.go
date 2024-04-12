package wiretunnel

import (
	"context"
	"net"

	"github.com/botanica-consulting/wiredialer"
)

// NewDialer returns a new wiredialer.WireDialer from a WireGuard configuration file.
func NewDialer(path string) (*wiredialer.WireDialer, error) {
	return wiredialer.NewDialerFromFile(path)
}

var systemDNS bool

// UseSystemDNS sets the resolver to resolve hostnames locally instead of remotely in the WireGuard network.
func UseSystemDNS() {
	systemDNS = true
	net.DefaultResolver.PreferGo = true
}

// DialWithSystemDNS returns a wrapped dial function that uses the system resolver to resolve hostnames.
func DialWithSystemDNS(dial func(context.Context, string, string) (net.Conn, error)) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}

		addrs, err := net.DefaultResolver.LookupHost(ctx, host)
		if err != nil {
			return nil, err
		}

		host = addrs[0]
		address = net.JoinHostPort(host, port)
		return dial(ctx, network, address)
	}
}
