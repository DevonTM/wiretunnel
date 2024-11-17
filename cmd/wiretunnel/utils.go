package main

import (
	"net"
	"strings"
)

func parseBypassList(list string) []*net.IPNet {
	var netIPs []*net.IPNet

	for _, s := range strings.Split(list, ",") {
		_, ipnet, err := net.ParseCIDR(s)
		if err == nil {
			netIPs = append(netIPs, ipnet)
			continue
		}

		ip := net.ParseIP(s)
		if ip != nil {
			var ipnet *net.IPNet
			if ip.To4() != nil {
				ipnet = &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}
			} else {
				ipnet = &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
			}
			netIPs = append(netIPs, ipnet)
		}
	}

	return netIPs
}
