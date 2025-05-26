package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/Mpinyaz/GinWebApp/config"
	"github.com/Mpinyaz/GinWebApp/internal/auth"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type AuthMiddleware struct {
	AuthService *auth.AuthService
	CTX         *context.Context
}

func NewAuthMiddleware(DB *gorm.DB, Config *config.AppCfg, CTX *context.Context) AuthMiddleware {
	return AuthMiddleware{AuthService: auth.NewAuthService(DB, Config), CTX: CTX}
}

func (am *AuthMiddleware) VerifyAccessTokenMiddleware(tokenPublicKey string) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		// First check for access token in the Authorization header
		authHeader := ctx.GetHeader("Authorization")
		var accessToken string

		// Extract token from Authorization header if present
		if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
			accessToken = strings.TrimPrefix(authHeader, "Bearer ")
		} else {
			// If not in header, try to get from cookie
			var err error
			accessToken, err = ctx.Cookie("access_token")
			if err != nil {
				ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"status": "fail", "message": "You are not logged in"})
				return
			}
		}

		// Verify the access token
		claims, err := am.AuthService.VerifyAccessToken(accessToken, tokenPublicKey)
		if err != nil {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"status": "fail", "message": "Invalid access token: " + err.Error()})
			return
		}

		// Set user information in the context
		ctx.Set("user_id", claims.UserID)
		ctx.Set("user_role", claims.Role)
		ctx.Set("username", claims.Username)

		ctx.Next()
	}
}
