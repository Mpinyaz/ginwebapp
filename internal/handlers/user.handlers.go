package handlers

import (
	"net/http"

	"github.com/Mpinyaz/GinWebApp/internal/dtos"
	models "github.com/Mpinyaz/GinWebApp/internal/models/users"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type UserHandler struct {
	DB *gorm.DB
}

func NewUserHandler(DB *gorm.DB) UserHandler {
	return UserHandler{DB}
}

func (uh *UserHandler) GetProfile(ctx *gin.Context) {
	currentUser := ctx.MustGet("currentUser").(models.User)

	userResponse := &dtos.UserResponse{
		ID:        currentUser.ID,
		Username:  currentUser.Username,
		Email:     currentUser.Email,
		Role:      currentUser.Role.String(),
		CreatedAt: currentUser.CreatedAt,
		UpdatedAt: currentUser.UpdatedAt,
	}
	ctx.JSON(http.StatusOK, gin.H{"status": "success", "data": gin.H{"user": userResponse}})
}

