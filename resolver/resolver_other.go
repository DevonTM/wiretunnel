//go:build !linux && !windows
// +build !linux,!windows

package resolver

import (
	"errors"

	"github.com/miekg/dns"
)

// getConfig for other OS not implemented yet.
func GetConfig() (*dns.ClientConfig, error) {
	return nil, errors.New("not implemented")
}
