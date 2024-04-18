package resolver

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/botanica-consulting/wiredialer"
	"github.com/miekg/dns"
	"github.com/patrickmn/go-cache"
)

var (
	ErrNoNetwork    = errors.New("no network available")
	ErrNoARecord    = errors.New("no A record")
	ErrNoAAAARecord = errors.New("no AAAA record")
)

type Resolver struct {
	client  *dns.Client
	config  *dns.ClientConfig
	cache   *cache.Cache
	mutex   *sync.RWMutex
	udpSize uint16
	haveIP4 bool
	haveIP6 bool
}

// NewResolver creates a new Resolver.
func NewResolver(d *wiredialer.WireDialer) (*Resolver, error) {
	cfg, err := getConfig()
	if err != nil {
		return nil, err
	}

	r := &Resolver{
		client:  new(dns.Client),
		config:  cfg,
		cache:   cache.New(0, 10*time.Minute),
		mutex:   new(sync.RWMutex),
		udpSize: 1232,
	}

	var wg sync.WaitGroup
	wg.Add(2)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	go func() {
		defer wg.Done()
		conn, err := d.DialContext(ctx, "tcp", "1.1.1.1:53")
		if err == nil {
			conn.Close()
			r.haveIP4 = true
		}
	}()

	go func() {
		defer wg.Done()
		conn, err := d.DialContext(ctx, "tcp", "[2606:4700:4700::1111]:53")
		if err == nil {
			conn.Close()
			r.haveIP6 = true
		}
	}()

	wg.Wait()

	if !r.haveIP4 && !r.haveIP6 {
		return nil, ErrNoNetwork
	}

	return r, nil
}

// LookupHost looks up the given host using the local resolver.
func (r *Resolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	if net.ParseIP(host) != nil {
		return []string{host}, nil
	}

	r.mutex.RLock()
	c, ok := r.cache.Get(host)
	r.mutex.RUnlock()
	if ok {
		addrs, ok := c.([]string)
		if ok {
			return addrs, nil
		} else {
			return nil, r.errNoHost(host)
		}
	}

	var network string
	if r.haveIP4 && r.haveIP6 {
		network = "ip"
	} else if r.haveIP4 {
		network = "ip4"
	} else if r.haveIP6 {
		network = "ip6"
	} else {
		return nil, ErrNoNetwork
	}

	rec, err := r.lookupIP(ctx, network, host)
	if err != nil {
		r.mutex.Lock()
		r.cache.Set(host, nil, 5*time.Minute)
		r.mutex.Unlock()
		return nil, err
	}

	names := make([]string, len(rec.ips))
	for i, ip := range rec.ips {
		names[i] = ip.String()
	}

	r.mutex.Lock()
	r.cache.Set(host, names, time.Duration(rec.ttl)*time.Second)
	r.mutex.Unlock()
	return names, nil
}

type dnsRecord struct {
	ips []net.IP
	ttl uint32
}

func (r *Resolver) lookupIP(ctx context.Context, network, host string) (*dnsRecord, error) {
	var ip4, ip6 []net.IP
	var ttl uint32
	var wg sync.WaitGroup
	var mu sync.Mutex

	switch network {
	case "ip", "ip4":
		wg.Add(1)
		go func() {
			defer wg.Done()
			if rec, err := r.lookupA(ctx, host); err == nil {
				ip4 = rec.ips
				mu.Lock()
				ttl = rec.ttl
				mu.Unlock()
			}
		}()
	}

	switch network {
	case "ip", "ip6":
		wg.Add(1)
		go func() {
			defer wg.Done()
			if rec, err := r.lookupAAAA(ctx, host); err == nil {
				ip6 = rec.ips
				mu.Lock()
				ttl = rec.ttl
				mu.Unlock()
			}
		}()
	}

	wg.Wait()

	ips := combineIPs(ip6, ip4)
	if len(ips) == 0 {
		return nil, r.errNoHost(host)
	}

	return &dnsRecord{
		ips: ips,
		ttl: ttl,
	}, nil
}

func (r *Resolver) lookupA(ctx context.Context, host string) (*dnsRecord, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(host), dns.TypeA)
	m.SetEdns0(r.udpSize, true)
	rep, _, err := r.client.ExchangeContext(ctx, m, net.JoinHostPort(r.config.Servers[0], r.config.Port))
	if err != nil {
		return nil, err
	}

	if rep.Rcode != dns.RcodeSuccess || len(rep.Answer) == 0 {
		return nil, ErrNoARecord
	}

	var ips []net.IP
	for _, ans := range rep.Answer {
		if a, ok := ans.(*dns.A); ok {
			ips = append(ips, a.A)
		}
	}

	return &dnsRecord{
		ips: ips,
		ttl: rep.Answer[0].Header().Ttl,
	}, nil
}

func (r *Resolver) lookupAAAA(ctx context.Context, host string) (*dnsRecord, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(host), dns.TypeAAAA)
	m.SetEdns0(r.udpSize, true)
	rep, _, err := r.client.ExchangeContext(ctx, m, net.JoinHostPort(r.config.Servers[0], r.config.Port))
	if err != nil {
		return nil, err
	}

	if rep.Rcode != dns.RcodeSuccess || len(rep.Answer) == 0 {
		return nil, ErrNoAAAARecord
	}

	var ips []net.IP
	for _, ans := range rep.Answer {
		if aaaa, ok := ans.(*dns.AAAA); ok {
			ips = append(ips, aaaa.AAAA)
		}
	}

	return &dnsRecord{
		ips: ips,
		ttl: rep.Answer[0].Header().Ttl,
	}, nil
}

func combineIPs(ip1, ip2 []net.IP) []net.IP {
	ips := make([]net.IP, 0, len(ip1)+len(ip2))
	i1, i2 := 0, 0
	for i1 < len(ip1) || i2 < len(ip2) {
		if i1 < len(ip1) {
			ips = append(ips, ip1[i1])
			i1++
		}
		if i2 < len(ip2) {
			ips = append(ips, ip2[i2])
			i2++
		}
	}
	return ips
}

func (r *Resolver) errNoHost(host string) error {
	return &net.DNSError{
		Err:        "no such host",
		Name:       host + ".",
		Server:     r.config.Servers[0],
		IsNotFound: true,
	}
}
