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

func ViewRoutes(router *gin.Engine, db *gorm.DB, redis *redis.Client, cfg *config.AppCfg, ctx *context.Context) {
	authMiddleware := middleware.NewAuthMiddleware(db, cfg, ctx, redis)
	router.GET("/", handlers.ViewIndex)
	router.GET("/login", handlers.ViewLogin)
	router.GET("/register", handlers.ViewRegister)
	router.GET("/profile", (authMiddleware.VerifyAccessTokenMiddleware(cfg.AccessTokenPublicKey)), handlers.ViewProfile(db))
}
