package routes

import (
	"github.com/Mpinyaz/GinWebApp/internal/handlers"
	"github.com/Mpinyaz/GinWebApp/internal/middleware"
	"github.com/gin-gonic/gin"
)

type UserRouteHandler struct {
	userHandler    handlers.UserHandler
	authMiddleware middleware.AuthMiddleware
}

func NewUserRouteHandler(userHandler handlers.UserHandler, authMiddleware middleware.AuthMiddleware) UserRouteHandler {
	return UserRouteHandler{userHandler, authMiddleware}
}

func (uh *UserRouteHandler) UserRoute(rg *gin.RouterGroup) {
	router := rg.Group("users")
	router.Use(uh.authMiddleware.DeserializeUser())
	{
		router.GET("/me", uh.authMiddleware.DeserializeUser(), uh.userHandler.GetProfile)
	}
}
