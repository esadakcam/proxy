package web

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/esadakcam/proxy/internal/config"
)

func TestHandlerProxiesAllowedHost(t *testing.T) {
	var receivedURL string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedURL = r.URL.RequestURI()
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(upstream.Close)

	handler, err := NewHandler(&config.Config{
		ProxyBase: upstream.URL + "/proxy",
		Domains:   []string{"example.com"},
	})
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/original/path?one=1&two=2", nil)
	req.Host = "example.com:8080"
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusNoContent)
	}
	if want := "/proxy/example.com/original/path?one=1&two=2"; receivedURL != want {
		t.Fatalf("upstream request URI = %q, want %q", receivedURL, want)
	}
}

func TestHandlerRejectsUnknownHost(t *testing.T) {
	handler, err := NewHandler(&config.Config{
		ProxyBase: "http://127.0.0.1:1",
		Domains:   []string{"example.com"},
	})
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://unknown.example/path", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusForbidden)
	}
}
