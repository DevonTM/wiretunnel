package wiretunnel

import (
	"context"
	"net"

	"github.com/botanica-consulting/wiredialer"
	"github.com/things-go/go-socks5"
)

type SOCKS5Server struct {
	Address  string
	Username string
	Password string

	Dialer *wiredialer.WireDialer
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
	if systemDNS {
		return s.localResolve(ctx, name)
	}
	return s.wgResolve(ctx, name)
}

func (s *SOCKS5Server) localResolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", name)
	if err != nil {
		return ctx, nil, err
	}
	return ctx, ips[0], nil
}

func (s *SOCKS5Server) wgResolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	addrs, err := s.Dialer.LookupContextHost(ctx, name)
	if err != nil {
		return ctx, nil, err
	}
	ip := net.ParseIP(addrs[0])
	return ctx, ip, nil
}
