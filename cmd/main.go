package main

import (
	"fmt"
	"os"

	"github.com/esadakcam/proxy/internal/cert"
	"github.com/esadakcam/proxy/internal/config"
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

	fmt.Println(cfg)
	pair, err := cert.GenerateKeyAndCert(cfg.Domains, cfg.CaCert, cfg.CaKey)
	if err != nil {
		panic(err)
	}
	fmt.Println(pair)
}
