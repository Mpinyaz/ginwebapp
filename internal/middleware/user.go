package middleware

import (
	"errors"
	"net/http"
	"strings"

	"github.com/Mpinyaz/GinWebApp/config"
	"github.com/Mpinyaz/GinWebApp/internal/repositories"
	"github.com/Mpinyaz/GinWebApp/internal/utils"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type AuthMiddleware struct {
	DB     *gorm.DB
	Config *config.AppConfig
}

func NewAuthMiddleware(db *gorm.DB, config *config.AppConfig) AuthMiddleware {
	return AuthMiddleware{
		DB:     db,
		Config: config,
	}
}

func (am *AuthMiddleware) DeserializeUser() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		var accessToken string
		userRepo := repositories.NewUserRepository(am.DB)
		cookie, err := ctx.Cookie("access_token")
		authorizationHeader := ctx.Request.Header.Get("Authorization")
		fields := strings.Fields(authorizationHeader)

		if len(fields) == 2 && strings.ToLower(fields[0]) == "bearer" {
			accessToken = fields[1]
		} else if err == nil {
			accessToken = cookie
		}

		if accessToken == "" {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"status": "fail", "message": "You are not logged in"})
			return
		}

		claim, err := utils.VerifyToken(accessToken, "access_token", am.Config.AccessTokenPublicKey)
		if err != nil {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"status": "fail", "message": "Invalid token: " + err.Error()})
			return
		}

		user, err := userRepo.FindByID(claim.UserID)
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				ctx.AbortWithStatusJSON(http.StatusForbidden, gin.H{"status": "fail", "message": "The user belonging to this token no longer exists"})
			} else {
				ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "Database error: " + err.Error()})
			}
			return
		}

		ctx.Set("currentUser", *user)
		ctx.Next()
	}
}
