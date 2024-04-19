//go:build linux
// +build linux

package resolver

import "github.com/miekg/dns"

// getConfig returns the DNS configuration from the Linux resolv.conf file.
func GetConfig() (*dns.ClientConfig, error) {
	return dns.ClientConfigFromFile("/etc/resolv.conf")
}
