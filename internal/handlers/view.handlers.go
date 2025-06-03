package handlers

import (
	"net/http"

	"github.com/Mpinyaz/GinWebApp/internal/dtos"
	"github.com/Mpinyaz/GinWebApp/internal/repositories"
	utils "github.com/Mpinyaz/GinWebApp/internal/utils"
	"github.com/Mpinyaz/GinWebApp/internal/views/pages"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func ViewIndex(c *gin.Context) {
	cookie, _ := c.Cookie("session_token")
	if cookie != "" {
		utils.Render(c, http.StatusOK, pages.Index(true))
	} else {
		utils.Render(c, http.StatusOK, pages.Index(false))
	}
}

func ViewRegister(c *gin.Context) {
	cookie, _ := c.Cookie("session_token")
	if cookie != "" {
		c.Redirect(http.StatusFound, "/")
	}

	utils.Render(c, http.StatusOK, pages.Register())
}

func ViewLogin(c *gin.Context) {
	cookie, _ := c.Cookie("session_token")
	if cookie != "" {
		c.Redirect(http.StatusFound, "/")
	}

	utils.Render(c, http.StatusOK, pages.LogIn())
}

func ViewProfile(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		username, exists := c.Get("username")
		if !exists {
			utils.Render(c, http.StatusForbidden, pages.PageNotFound("Access forbidden"))
			return
		}

		usernameStr, ok := username.(string)
		if !ok {
			utils.Render(c, http.StatusInternalServerError, pages.PageNotFound("Invalid session data"))
			return
		}

		userRepo := repositories.NewUserRepository(db)
		currentUser, err := userRepo.FindByUserame(usernameStr)
		if err != nil {
			utils.Render(c, http.StatusInternalServerError, pages.PageNotFound("Internal error: cannot access right now"))
			return
		}

		userResponse := &dtos.UserResponse{
			ID:        currentUser.ID,
			Username:  currentUser.Username,
			Email:     currentUser.Email,
			Role:      currentUser.Role.String(),
			CreatedAt: currentUser.CreatedAt,
			UpdatedAt: currentUser.UpdatedAt,
		}

		utils.Render(c, http.StatusOK, pages.Profile(true, userResponse))
	}
}

func NotFound(c *gin.Context) {
	c.Header("Content-Type", "text/html; charset=utf-8")
	utils.Render(c, http.StatusOK, pages.PageNotFound("Better Luck Next Time"))
}
