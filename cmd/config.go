package main

import (
	"errors"
	"fmt"
	"os"
)

const VERSION = "0.0.0"

var (
	wgConfigPath string

	httpAddr string
	httpUser string
	httpPass string

	socks5Addr string
	socks5User string
	socks5Pass string

	systemDNS bool

	showVersion bool
)

func configParse() error {
	env := os.Getenv("WG_CONFIG")
	if wgConfigPath == "" {
		wgConfigPath = env
	}

	env = os.Getenv("HTTP_ADDR")
	if (httpAddr == "" || httpAddr == ":8080") && env != "" {
		httpAddr = env
	}

	env = os.Getenv("HTTP_USER")
	if httpUser == "" {
		httpUser = env
	}

	env = os.Getenv("HTTP_PASS")
	if httpPass == "" {
		httpPass = env
	}

	env = os.Getenv("SOCKS5_ADDR")
	if (socks5Addr == "" || socks5Addr == ":1080") && env != "" {
		socks5Addr = env
	}

	env = os.Getenv("SOCKS5_USER")
	if socks5User == "" {
		socks5User = env
	}

	env = os.Getenv("SOCKS5_PASS")
	if socks5Pass == "" {
		socks5Pass = env
	}

	env = os.Getenv("SYSTEM_DNS")
	if !systemDNS {
		systemDNS = env == "true"
	}

	if wgConfigPath == "" {
		return errors.New("WireGuard configuration file is required")
	}

	if httpAddr == "" {
		return errors.New("HTTP server address is required")
	}

	if socks5Addr == "" {
		return errors.New("SOCKS5 server address is required")
	}

	return nil
}

func printVersion() {
	fmt.Printf("WireTunnel v%s\n", VERSION)
}
