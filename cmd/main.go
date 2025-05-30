package main

import (
	"context"
	"fmt"
	"log"

	"github.com/Mpinyaz/GinWebApp/config"
	"github.com/Mpinyaz/GinWebApp/db"
	"github.com/Mpinyaz/GinWebApp/internal/cache"
	"github.com/Mpinyaz/GinWebApp/internal/routes"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

func main() {
	cfg, err := config.LoadConfig("../.")
	if err != nil {
		log.Fatalf("failed to load configuration: %v", err)
	}

	ctx := context.Background()

	redisClient, err := cache.ConnectRedis(cfg)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	dbConn, err := db.ConnectPGDB(cfg)
	if err != nil {
		log.Fatalf("Error connecting to Postgres database: %v", err)
	}

	router := gin.Default()
	corsConfig := cors.DefaultConfig()
	dm := fmt.Sprintf("http://localhost:%d", cfg.Port)
	corsConfig.AllowOrigins = []string{dm, cfg.ClientOrigin}
	corsConfig.AllowCredentials = true

	router.Use(cors.New(corsConfig))
	routes.AuthRoutes(router, dbConn, redisClient, cfg, &ctx)

	log.Printf("Server starting on port %d", cfg.Port)
	if err := router.Run(fmt.Sprintf(":%d", cfg.Port)); err != nil {
		log.Fatalf("failed to start server: %v", err)
	}
}
