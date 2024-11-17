# Wiretunnel

Wiretunnel is a userspace WireGuard client that acts as a proxy server. It supports HTTP and SOCKS5 proxies with UDP associate.

## Features

- HTTP proxy

- SOCKS5 proxy with UDP associate support

- Choose between remote or local address resolution

## Usage

```bash
./wiretunnel -cfg /path/to/wireguard/config
```

### Flags

- `-cfg string`: WireGuard configuration file path. $WG_CONFIG

- `-haddr string`: HTTP server address, set '0' to disable, default ':8080'. $HTTP_ADDR

- `-huser string`: HTTP proxy username. $HTTP_USER

- `-hpass string`: HTTP proxy password. $HTTP_PASS

- `-saddr string`: SOCKS5 server address, set '0' to disable, default ':1080'. $SOCKS5_ADDR

- `-suser string`: SOCKS5 proxy username. $SOCKS5_USER

- `-spass string`: SOCKS5 proxy password. $SOCKS5_PASS

- `-bl string`: Bypass list of IPs separated by comma. $BYPASS_LIST

- `-ldns boolean`: Resolve address locally. $LOCAL_DNS

- `-log boolean`: Enable logging to stdout. $ENABLE_LOG

- `-v boolean`: Print version and exit

## Compile

```bash
go build ./cmd/wiretunnel
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
