package handlers

import (
	"net/http"

	utils "github.com/Mpinyaz/GinWebApp/internal/utils"
	"github.com/Mpinyaz/GinWebApp/internal/views/pages"
	"github.com/gin-gonic/gin"
)

func ViewIndex(c *gin.Context) {
	cookie, _ := c.Cookie("session_token")
	if cookie != "" {
		utils.Render(c, http.StatusOK, pages.Index(true))
	}

	utils.Render(c, http.StatusOK, pages.Index(false))
}

func ViewRegister(c *gin.Context) {
	cookie, _ := c.Cookie("session_token")
	if cookie != "" {
		c.Redirect(http.StatusFound, "/")
	}

	utils.Render(c, http.StatusOK, pages.Register())
}
