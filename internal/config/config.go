package config

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"os"

	"github.com/esadakcam/proxy/internal/cert"
)

type config struct {
	CaCert    string   `json:"caCert"`
	CaKey     string   `json:"caKey"`
	ProxyBase string   `json:"proxyBase"`
	Domains   []string `json:"domains"`
}

type Config struct {
	CaCert    *x509.Certificate
	CaKey     *rsa.PrivateKey
	ProxyBase string
	Domains   []string
}

func Parse(path string) (*Config, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var config config
	err = json.Unmarshal(contents, &config)
	if err != nil {
		return nil, err
	}
	caCert, err := cert.LoadCert(config.CaCert)
	if err != nil {
		return nil, err
	}

	caKey, err := cert.LoadKey(config.CaKey)
	if err != nil {
		return nil, err
	}

	return &Config{
		CaKey:     caKey,
		CaCert:    caCert,
		ProxyBase: config.ProxyBase,
		Domains:   config.Domains,
	}, nil
}
