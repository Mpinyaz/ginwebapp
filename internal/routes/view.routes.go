package routes

import (
	"github.com/Mpinyaz/GinWebApp/internal/handlers"
	"github.com/gin-gonic/gin"
)

func ViewRoutes(router *gin.Engine) {
	router.GET("/", handlers.ViewIndex)

	router.GET("/register", handlers.ViewRegister)
}
