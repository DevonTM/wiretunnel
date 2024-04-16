module github.com/DevonTM/wiretunnel

go 1.22

require (
	github.com/botanica-consulting/wiredialer v0.0.0-20230710124424-ca42731e9a5c
	github.com/miekg/dns v1.1.58
	github.com/patrickmn/go-cache v2.1.0+incompatible
	github.com/things-go/go-socks5 v0.0.5
	golang.org/x/sys v0.19.0
)

require (
	github.com/google/btree v1.1.2 // indirect
	golang.org/x/crypto v0.22.0 // indirect
	golang.org/x/mod v0.17.0 // indirect
	golang.org/x/net v0.24.0 // indirect
	golang.org/x/sync v0.7.0 // indirect
	golang.org/x/time v0.5.0 // indirect
	golang.org/x/tools v0.20.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
	golang.zx2c4.com/wireguard v0.0.0-20231211153847-12269c276173 // indirect
	gvisor.dev/gvisor v0.0.0-20240315190121-2be91ac8c110 // indirect
)

replace github.com/botanica-consulting/wiredialer => github.com/DevonTM/wiredialer v0.1.1
