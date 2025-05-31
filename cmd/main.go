package main

import (
	"context"
	"embed"
	"fmt"
	"log"
	"net/http"

	"github.com/Mpinyaz/GinWebApp/config"
	"github.com/Mpinyaz/GinWebApp/db"
	"github.com/Mpinyaz/GinWebApp/internal/cache"
	"github.com/Mpinyaz/GinWebApp/internal/routes"
	"github.com/Mpinyaz/GinWebApp/internal/utils"
	pages "github.com/Mpinyaz/GinWebApp/internal/views/pages"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

var staticFiles embed.FS

func main() {
	cfg, err := config.LoadConfig(".")
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
	router.Static("/static", "./static")
	corsConfig := cors.DefaultConfig()
	dm := fmt.Sprintf("http://localhost:%d", cfg.Port)
	corsConfig.AllowOrigins = []string{dm, cfg.ClientOrigin}
	corsConfig.AllowCredentials = true

	router.Use(cors.New(corsConfig))
	router.GET("/", func(c *gin.Context) {
		cookie, _ := c.Cookie("session_token")
		if cookie != "" {
			utils.Render(c, http.StatusOK, pages.Index(true))
		}

		utils.Render(c, http.StatusOK, pages.Index(false))
	})

	routes.AuthRoutes(router, dbConn, redisClient, cfg, &ctx)

	log.Printf("Server starting on port %d", cfg.Port)
	if err := router.Run(fmt.Sprintf(":%d", cfg.Port)); err != nil {
		log.Fatalf("failed to start server: %v", err)
	}
}
