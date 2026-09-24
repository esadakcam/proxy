package web

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/esadakcam/proxy/internal/cert"
	"github.com/esadakcam/proxy/internal/config"
)

// NewHandler creates the HTTP handler used by both the HTTP and HTTPS
// listeners. The proxy base is parsed once, when the handler is created.
func NewHandler(cfg *config.Config) (http.Handler, error) {
	if cfg == nil {
		return nil, errors.New("config is required")
	}

	proxyBase, err := url.Parse(cfg.ProxyBase)
	if err != nil {
		return nil, fmt.Errorf("parse proxy base: %w", err)
	}
	if proxyBase.Scheme == "" || proxyBase.Host == "" {
		return nil, errors.New("proxy base must be an absolute URL")
	}

	allowedDomains := make(map[string]struct{}, len(cfg.Domains))
	for _, domain := range cfg.Domains {
		allowedDomains[normalizeHostname(domain)] = struct{}{}
	}

	proxy := httputil.NewSingleHostReverseProxy(proxyBase)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hostname := normalizeHostname(r.Host)
		if _, allowed := allowedDomains[hostname]; !allowed {
			http.Error(w, "host not allowed", http.StatusForbidden)
			return
		}

		// NewSingleHostReverseProxy joins this path to ProxyBase's path and
		// leaves RawQuery untouched.
		r.URL.Path = "/" + hostname + "/" + strings.TrimPrefix(r.URL.Path, "/")
		r.URL.RawPath = ""
		proxy.ServeHTTP(w, r)
	}), nil
}

func normalizeHostname(host string) string {
	if hostname, _, err := net.SplitHostPort(host); err == nil {
		host = hostname
	}
	return strings.ToLower(strings.TrimSuffix(host, "."))
}

// Serve starts the HTTP and HTTPS listeners and blocks until a listener exits.
// If either listener fails, the other is closed and all non-shutdown errors are
// returned to the caller.
func Serve(cfg *config.Config, pair *cert.CertKeyPair) error {
	handler, err := NewHandler(cfg)
	if err != nil {
		return err
	}
	if pair == nil || pair.Cert == nil || pair.Key == nil {
		return errors.New("certificate and private key are required")
	}

	tlsCertificate := tls.Certificate{
		Certificate: [][]byte{pair.Cert.Raw},
		PrivateKey:  pair.Key,
		Leaf:        pair.Cert,
	}
	httpServer := &http.Server{Addr: ":80", Handler: handler}
	httpsServer := &http.Server{
		Addr:    ":443",
		Handler: handler,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{tlsCertificate},
			MinVersion:   tls.VersionTLS12,
		},
	}

	errorsCh := make(chan error, 2)
	go func() { errorsCh <- httpServer.ListenAndServe() }()
	go func() { errorsCh <- httpsServer.ListenAndServeTLS("", "") }()

	firstErr := <-errorsCh
	_ = httpServer.Close()
	_ = httpsServer.Close()
	secondErr := <-errorsCh

	return errors.Join(listenerError(firstErr), listenerError(secondErr))
}

func listenerError(err error) error {
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
