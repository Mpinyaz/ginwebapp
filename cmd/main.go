package main

import (
	"context"
	"log"

	"github.com/Mpinyaz/GinWebApp/config"
)

func main() {
	cfg, err := config.LoadConfig(".")
	if err != nil {
		log.Fatalf("failed to load configuration: %v", err)
	}

	ctx := context.Background()
	ctx = config.WithConfig(ctx, cfg)
}
