package main

import (
	"flag"
	"fmt"
	"log"
	"sync"

	"github.com/DevonTM/wiretunnel"
)

func init() {
	flag.StringVar(&wgConfigPath, "cfg", "", "WireGuard configuration file `path`\n$WG_CONFIG")
	flag.StringVar(&httpAddr, "haddr", "", "HTTP server `address`, set '0' to disable, default ':8080'\n$HTTP_ADDR")
	flag.StringVar(&httpUser, "huser", "", "HTTP proxy `username`\n$HTTP_USER")
	flag.StringVar(&httpPass, "hpass", "", "HTTP proxy `password`\n$HTTP_PASS")
	flag.StringVar(&socks5Addr, "saddr", "", "SOCKS5 server `address`, set '0' to disable, default ':1080'\n$SOCKS5_ADDR")
	flag.StringVar(&socks5User, "suser", "", "SOCKS5 proxy `username`\n$SOCKS5_USER")
	flag.StringVar(&socks5Pass, "spass", "", "SOCKS5 proxy `password`\n$SOCKS5_PASS")
	flag.BoolVar(&localDNS, "ldns", false, "Resolve address locally\n$LOCAL_DNS")
	flag.BoolVar(&showVersion, "v", false, "Print version and exit")
	flag.Parse()
}

func main() {
	printVersion()
	if showVersion {
		return
	}

	err := configParse()
	if err != nil {
		log.Fatal(fmt.Errorf("Config: ERROR: %w", err))
	}

	d, err := wiretunnel.NewDialer(wgConfigPath)
	if err != nil {
		log.Fatal(fmt.Errorf("WireGuard: ERROR: %w", err))
	}

	r, err := wiretunnel.NewResolver(d, localDNS)
	if err != nil {
		log.Fatal(fmt.Errorf("Resolver: ERROR: %w", err))
	}

	var wg sync.WaitGroup

	if httpAddr != "0" {
		wg.Add(1)
		go func() {
			httpServer := &wiretunnel.HTTPServer{
				Address:  httpAddr,
				Username: httpUser,
				Password: httpPass,
				Dialer:   d,
				Resolver: r,
			}
			log.Println("HTTP proxy server: listening on", httpAddr)
			err := httpServer.ListenAndServe()
			if err != nil {
				log.Printf("HTTP proxy server: ERROR: %v", err)
			}
			wg.Done()
		}()
	}

	if socks5Addr != "0" {
		wg.Add(1)
		go func() {
			socks5Server := &wiretunnel.SOCKS5Server{
				Address:  socks5Addr,
				Username: socks5User,
				Password: socks5Pass,
				Dialer:   d,
				Resolver: r,
			}
			log.Println("SOCKS5 proxy server: listening on", socks5Addr)
			err := socks5Server.ListenAndServe()
			if err != nil {
				log.Printf("SOCKS5 proxy server: ERROR: %v", err)
			}
			wg.Done()
		}()
	}

	wg.Wait()
}
