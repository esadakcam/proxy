package main

import (
	"os"

	"github.com/esadakcam/proxy/internal/cert"
	"github.com/esadakcam/proxy/internal/config"
	"github.com/esadakcam/proxy/internal/web"
)

func main() {
	if len(os.Args) < 2 {
		panic("config required")
	}
	configPath := os.Args[1]

	cfg, err := config.Parse(configPath)
	if err != nil {
		panic(err)
	}

	pair, err := cert.GenerateKeyAndCert(cfg.Domains, cfg.CaCert, cfg.CaKey)
	if err != nil {
		panic(err)
	}

	if err := web.Serve(cfg, pair); err != nil {
		panic(err)
	}
}
