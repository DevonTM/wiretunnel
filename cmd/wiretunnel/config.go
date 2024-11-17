package main

import (
	"errors"
	"fmt"
	"os"
)

const VERSION = "1.2.0"

var (
	wgConfigPath string

	httpAddr string
	httpUser string
	httpPass string

	socks5Addr string
	socks5User string
	socks5Pass string

	bypassList string
	localDNS   bool
	enableLog  bool

	showVersion bool
)

func configParse() error {
	if wgConfigPath == "" {
		wgConfigPath = os.Getenv("WG_CONFIG")
	}

	if httpAddr == "" {
		httpAddr = os.Getenv("HTTP_ADDR")
	}

	if httpUser == "" {
		httpUser = os.Getenv("HTTP_USER")
	}

	if httpPass == "" {
		httpPass = os.Getenv("HTTP_PASS")
	}

	if socks5Addr == "" {
		socks5Addr = os.Getenv("SOCKS5_ADDR")
	}

	if socks5User == "" {
		socks5User = os.Getenv("SOCKS5_USER")
	}

	if socks5Pass == "" {
		socks5Pass = os.Getenv("SOCKS5_PASS")
	}

	if bypassList == "" {
		bypassList = os.Getenv("BYPASS_LIST")
	}

	if !localDNS {
		localDNS = os.Getenv("LOCAL_DNS") == "true"
	}

	if !enableLog {
		enableLog = os.Getenv("ENABLE_LOG") == "true"
	}

	if wgConfigPath == "" {
		return errors.New("WireGuard configuration file is required")
	}

	if httpAddr == "" {
		httpAddr = ":8080"
	}

	if socks5Addr == "" {
		socks5Addr = ":1080"
	}

	return nil
}

func printVersion() {
	fmt.Printf("WireTunnel v%s\n", VERSION)
}
