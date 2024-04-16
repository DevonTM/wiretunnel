package wiretunnel

import (
	"context"
	"net"

	"github.com/DevonTM/wiretunnel/resolver"
	"github.com/botanica-consulting/wiredialer"
	"github.com/things-go/go-socks5"
)

type SOCKS5Server struct {
	Address  string
	Username string
	Password string

	Dialer   *wiredialer.WireDialer
	Resolver *resolver.Resolver
}

// ListenAndServe listens on the s.Address and serves SOCKS5 requests.
func (s *SOCKS5Server) ListenAndServe() error {
	var authMethod socks5.Authenticator
	if s.Username != "" {
		authMethod = socks5.UserPassAuthenticator{
			Credentials: socks5.StaticCredentials{
				s.Username: s.Password,
			},
		}
	} else {
		authMethod = socks5.NoAuthAuthenticator{}
	}

	server := socks5.NewServer(
		socks5.WithAuthMethods([]socks5.Authenticator{authMethod}),
		socks5.WithDial(s.Dialer.DialContext),
		socks5.WithResolver(s),
	)

	return server.ListenAndServe("tcp", s.Address)
}

// Resolve implements the socks5.Resolver interface.
func (s *SOCKS5Server) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	var addrs []string
	var err error
	if s.Resolver != nil {
		addrs, err = s.Resolver.LookupHost(name)
	} else {
		addrs, err = s.Dialer.LookupContextHost(ctx, name)
	}
	if err != nil {
		return ctx, nil, err
	}
	ip := net.ParseIP(addrs[0])
	return ctx, ip, nil
}
