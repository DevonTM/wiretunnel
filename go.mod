module github.com/DevonTM/wiretunnel

go 1.24.3

require (
	github.com/botanica-consulting/wiredialer v0.0.0-20230710124424-ca42731e9a5c
	github.com/miekg/dns v1.1.62
	github.com/patrickmn/go-cache v2.1.0+incompatible
	github.com/txthinking/runnergroup v0.0.0-20241009114647-a2ed56ecb960
	github.com/txthinking/socks5 v0.0.0-20230325130024-4230056ae301
)

require (
	github.com/google/btree v1.1.3 // indirect
	golang.org/x/crypto v0.29.0 // indirect
	golang.org/x/mod v0.22.0 // indirect
	golang.org/x/net v0.31.0 // indirect
	golang.org/x/sync v0.9.0 // indirect
	golang.org/x/sys v0.27.0 // indirect
	golang.org/x/time v0.8.0 // indirect
	golang.org/x/tools v0.27.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
	golang.zx2c4.com/wireguard v0.0.0-20231211153847-12269c276173 // indirect
	gvisor.dev/gvisor v0.0.0-20241115110947-0ffdb7ae1c32 // indirect
)

replace (
	github.com/botanica-consulting/wiredialer => github.com/DevonTM/wiredialer v0.0.0-20240417131724-b23e84cbc1fe
	// use forked wireguard-go to fix removed isNil() in newer gvisor version
	golang.zx2c4.com/wireguard => github.com/DevonTM/wireguard-go v0.0.0-20240819151436-3cce9150af4b
)
