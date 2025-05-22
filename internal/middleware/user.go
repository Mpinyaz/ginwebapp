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

// func (am *AuthMiddleware) DeserializeUser() gin.HandlerFunc {
// return func(ctx *gin.Context) {
// 	var accessToken string
// 	userRepo := repositories.NewUserRepository(am.AuthService.DB)
// 	cookie, err := ctx.Cookie("access_token")
// 	authorizationHeader := ctx.Request.Header.Get("Authorization")
// 	fields := strings.Fields(authorizationHeader)
//
// 	if len(fields) == 2 && strings.ToLower(fields[0]) == "bearer" {
// 		accessToken = fields[1]
// 	} else if err == nil {
// 		accessToken = cookie
// 	}
//
// 	if accessToken == "" {
// 		ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"status": "fail", "message": "You are not logged in"})
// 		return
// 	}
//
// 	claim, err := auth.VerifyToken(accessToken, "access_token", am.Config.AccessTokenPublicKey)
// 	if err != nil {
// 		ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"status": "fail", "message": "Invalid token: " + err.Error()})
// 		return
// 	}
//
// 	user, err := userRepo.FindByID(claim.UserID)
// 	if err != nil {
// 		if errors.Is(err, gorm.ErrRecordNotFound) {
// 			ctx.AbortWithStatusJSON(http.StatusForbidden, gin.H{"status": "fail", "message": "The user belonging to this token no longer exists"})
// 		} else {
// 			ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "Database error: " + err.Error()})
// 		}
// 		return
// 	}
//
// 	ctx.Set("currentUser", *user)
// 	ctx.Next()
// }
// }

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
