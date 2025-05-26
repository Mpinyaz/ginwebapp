package routes

import (
	"context"

	"github.com/Mpinyaz/GinWebApp/config"
	"github.com/Mpinyaz/GinWebApp/internal/handlers"
	middleware "github.com/Mpinyaz/GinWebApp/internal/middleware"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"gorm.io/gorm"
)

func AuthRoutes(router *gin.Engine, db *gorm.DB, redis *redis.Client, cfg *config.AppCfg, ctx *context.Context) {
	authHandler := handlers.NewAuthHandler(db, redis, cfg, ctx)
	authMiddleware := middleware.NewAuthMiddleware(db, cfg, ctx)

	publicAuth := router.Group("/api/auth")
	publicAuth.POST("/register", authHandler.RegisterHandler)
	publicAuth.POST("/login", authHandler.LoginHandler)

	protectedAuth := router.Group("/api/auth")
	protectedAuth.Use(authMiddleware.VerifyAccessTokenMiddleware(cfg.AccessTokenPublicKey))
	protectedAuth.POST("/logout", authHandler.Logout)
	protectedAuth.POST("/refresh", authHandler.RefreshTokensHandler)
}
