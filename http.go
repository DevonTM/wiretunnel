package wiretunnel

import (
	"context"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
)

type HTTPServer struct {
	Address  string
	Username string
	Password string

	Dial func(context context.Context, network, address string) (net.Conn, error)

	transport *http.Transport
}

// ListenAndServe listens on the s.Address and serves HTTP requests.
func (s *HTTPServer) ListenAndServe() error {
	if systemDNS {
		s.Dial = DialWithSystemDNS(s.Dial)
	}

	s.transport = &http.Transport{
		DialContext:         s.Dial,
		DisableCompression:  true,
		MaxIdleConnsPerHost: 100,
	}

	server := &http.Server{
		Addr:    s.Address,
		Handler: s,
	}

	return server.ListenAndServe()
}

// ServeHTTP implements the http.Handler interface.
func (s *HTTPServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if s.Username != "" && !s.authenticate(r.Header) {
		w.Header().Set("Proxy-Authenticate", `Basic realm="`+http.StatusText(http.StatusProxyAuthRequired)+`"`)
		http.Error(w, http.StatusText(http.StatusProxyAuthRequired), http.StatusProxyAuthRequired)
		return
	}

	switch r.Method {
	case http.MethodConnect:
		s.handleConnect(w, r)
	default:
		s.handleOther(w, r)
	}
}

var connectSuccess = []byte(" 200 Connection Established\r\n\r\n")

func (s *HTTPServer) handleConnect(w http.ResponseWriter, r *http.Request) {
	peer, err := s.Dial(r.Context(), "tcp", r.Host)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer peer.Close()

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	conn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer conn.Close()

	_, err = conn.Write(append([]byte(r.Proto), connectSuccess...))
	if err != nil {
		return
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		io.Copy(peer, conn)
		wg.Done()
	}()

	go func() {
		io.Copy(conn, peer)
		wg.Done()
	}()

	wg.Wait()
}

func (s *HTTPServer) handleOther(w http.ResponseWriter, r *http.Request) {
	laddr, err := getLocalAddr(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	if r.Host == laddr {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	r.URL.Host = r.Host
	r.URL.Scheme = "http"
	r.RequestURI = ""

	delHopHeaders(r.Header)
	resp, err := s.transport.RoundTrip(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	delHopHeaders(resp.Header)
	for k, v := range resp.Header {
		w.Header()[k] = v
	}

	w.WriteHeader(resp.StatusCode)
	_, err = io.Copy(w, resp.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (s *HTTPServer) authenticate(header http.Header) bool {
	authHeader := header.Get("Proxy-Authorization")
	if authHeader == "" {
		return false
	}

	encodedCreds := authHeader[6:]
	creds, err := base64.StdEncoding.DecodeString(encodedCreds)
	if err != nil {
		return false
	}

	pair := strings.SplitN(string(creds), ":", 2)
	return pair[0] == s.Username && pair[1] == s.Password
}

var hopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Connection",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailers",
	"Transfer-Encoding",
	"Upgrade",
}

func delHopHeaders(header http.Header) {
	for _, h := range hopHeaders {
		header.Del(h)
	}
}

func getLocalAddr(ctx context.Context) (string, error) {
	addr, ok := ctx.Value(http.LocalAddrContextKey).(net.Addr)
	if !ok {
		return "", http.ErrServerClosed
	}
	return addr.String(), nil
}
