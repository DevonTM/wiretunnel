package main

import (
	"flag"
	"log"
	"sync"

	"github.com/DevonTM/wiretunnel"
	"github.com/DevonTM/wiretunnel/resolver"
)

func init() {
	flag.StringVar(&wgConfigPath, "cfg", "", "WireGuard configuration file\n$WG_CONFIG")
	flag.StringVar(&httpAddr, "haddr", ":8080", "HTTP server address\n$HTTP_ADDR")
	flag.StringVar(&httpUser, "huser", "", "HTTP proxy username\n$HTTP_USER")
	flag.StringVar(&httpPass, "hpass", "", "HTTP proxy password\n$HTTP_PASS")
	flag.StringVar(&socks5Addr, "saddr", ":1080", "SOCKS5 server address\n$SOCKS5_ADDR")
	flag.StringVar(&socks5User, "suser", "", "SOCKS5 proxy username\n$SOCKS5_USER")
	flag.StringVar(&socks5Pass, "spass", "", "SOCKS5 proxy password\n$SOCKS5_PASS")
	flag.BoolVar(&localDNS, "ldns", false, "Resolve address with local DNS\n$LOCAL_DNS")
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
		log.Fatal(err)
	}

	d, err := wiretunnel.NewDialer(wgConfigPath)
	if err != nil {
		log.Fatal(err)
	}

	var r *resolver.Resolver
	if localDNS {
		r, err = resolver.NewResolver(d)
		if err != nil {
			log.Fatal(err)
		}
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		httpServer := &wiretunnel.HTTPServer{
			Address:  httpAddr,
			Username: httpUser,
			Password: httpPass,
			Dialer:   d,
			Resolver: r,
		}
		log.Println("HTTP proxy server listening on", httpAddr)
		err := httpServer.ListenAndServe()
		if err != nil {
			log.Print(err)
		}
		wg.Done()
	}()

	go func() {
		socks5Server := &wiretunnel.SOCKS5Server{
			Address:  socks5Addr,
			Username: socks5User,
			Password: socks5Pass,
			Dialer:   d,
			Resolver: r,
		}
		log.Println("SOCKS5 proxy server listening on", socks5Addr)
		err := socks5Server.ListenAndServe()
		if err != nil {
			log.Print(err)
		}
		wg.Done()
	}()

	wg.Wait()
}
