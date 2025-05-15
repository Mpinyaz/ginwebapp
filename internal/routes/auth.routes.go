package routes

import (
	"github.com/Mpinyaz/GinWebApp/internal/handlers"
	"github.com/Mpinyaz/GinWebApp/internal/middleware"
	"github.com/gin-gonic/gin"
)

type AuthRouteHandler struct {
	authHandler    handlers.AuthHandler
	authMiddleware middleware.AuthMiddleware
}

func NewAuthRouteHandler(authHandler handlers.AuthHandler, authMiddleware middleware.AuthMiddleware) AuthRouteHandler {
	return AuthRouteHandler{authHandler: authHandler, authMiddleware: authMiddleware}
}

func (ah *AuthRouteHandler) AuthRoute(rg *gin.RouterGroup) {
	router := rg.Group("/auth")

	router.POST("/register", ah.authHandler.RegisterHandler)
	router.POST("/login", ah.authHandler.LoginHandler)
	router.GET("/refresh", ah.authHandler.RefreshAccessTokenHandler)
	router.GET("/logout", ah.authMiddleware.DeserializeUser(), ah.authHandler.Logout)
}
