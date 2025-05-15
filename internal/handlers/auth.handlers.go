package handlers

import (
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

	config "github.com/Mpinyaz/GinWebApp/config"
	"github.com/Mpinyaz/GinWebApp/internal/dtos"
	auth "github.com/Mpinyaz/GinWebApp/internal/middleware"
	models "github.com/Mpinyaz/GinWebApp/internal/models/users"
	"github.com/Mpinyaz/GinWebApp/internal/repositories"
	"github.com/Mpinyaz/GinWebApp/internal/utils"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type AuthHandler struct {
	DB     *gorm.DB
	Config *config.AppConfig
}

func NewAuthHandler(DB *gorm.DB, Config *config.AppConfig) AuthHandler {
	return AuthHandler{DB, Config}
}

func (ac *AuthHandler) RegisterHandler(ctx *gin.Context) {
	var payload *dtos.RegisterRequest

	if err := ctx.ShouldBindJSON(&payload); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"status": "fail", "message": err.Error()})
		return
	}

	var existingUser models.User

	if result := ac.DB.Where("email = ?", payload.Email).First(&existingUser); result.RowsAffected > 0 {
		ctx.JSON(http.StatusConflict, gin.H{"status": "error", "message": "Email already registered"})
		return
	}

	if result := ac.DB.Where("username = ?", payload.Username).First(&existingUser); result.RowsAffected > 0 {
		ctx.JSON(http.StatusConflict, gin.H{"status": "error", "message": "Username already taken"})
		return
	}

	hashedPassword, err := utils.HashPassword(payload.Password)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "Failed to hash password"})
		return
	}

	now := time.Now().In(time.UTC)
	user := models.User{
		Username:  strings.ToLower(payload.Username),
		Email:     strings.ToLower(payload.Email),
		Password:  hashedPassword,
		Role:      models.RoleUser,
		Verified:  false,
		CreatedAt: now,
		UpdatedAt: now,
	}

	result := ac.DB.Create(&user)

	if result.Error != nil && strings.Contains(result.Error.Error(), "duplicate key value violates unique") {
		ctx.JSON(http.StatusConflict, gin.H{"status": "fail", "message": "User with that email already exists"})
		return
	} else if result.Error != nil {
		ctx.JSON(http.StatusBadGateway, gin.H{"status": "error", "message": "Something bad happened"})
		return
	}

	userResponse := &dtos.UserResponse{
		ID:        user.ID,
		Username:  user.Username,
		Email:     user.Email,
		Role:      user.Role.String(),
		Verified:  user.Verified,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
	}

	ctx.JSON(http.StatusCreated, gin.H{"status": "success", "data": gin.H{"user": userResponse}})

}

func (ac *AuthHandler) LoginHandler(ctx *gin.Context) {
	userRepo := repositories.NewUserRepository(ac.DB)
	var payload *dtos.LoginRequest

	if err := ctx.ShouldBindJSON(&payload); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"status": "fail", "message": err.Error()})
		return
	}

	var user *models.User
	var err error
	emailRegex := `^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,4}$`
	isValidEmail := regexp.MustCompile(emailRegex).MatchString(payload.LoginIndentifier)

	if isValidEmail {
		user, err = userRepo.FindByEmail(payload.LoginIndentifier)
	} else {
		user, err = userRepo.FindByUserame(payload.LoginIndentifier) // Corrected function name
	}

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			ctx.JSON(http.StatusBadRequest, gin.H{"status": "fail", "message": "Invalid email or Password"})
		} else {
			ctx.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "Database error: " + err.Error()}) //handle other db errors
		}
		return
	}

	if err := utils.VerifyPassword(user.Password, payload.Password); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"status": "fail", "message": "Invalid email or Password"})
		return
	}

	tokenInfo := utils.TokenConfig{
		AccessTokenSecret:    ac.Config.AccessTokenPrivateKey,
		AccessTokenDuration:  time.Duration(ac.Config.AccessTokenMaxAge) * time.Minute,
		RefreshTokenSecret:   ac.Config.RefreshTokenPrivateKey,
		RefreshTokenDuration: time.Duration(ac.Config.RefreshTokenMaxAge) * time.Minute,
		AccessTokenMaxAge:    ac.Config.AccessTokenMaxAge,
		RefreshTokenMaxAge:   ac.Config.RefreshTokenMaxAge,
	}

	tokens, err := utils.GenerateTokens(*user, ac.DB, tokenInfo)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "Failed to generate tokens"})
		return
	}

	// Set cookies for the tokens
	ctx.SetCookie("access_token", tokens.AccessToken, tokenInfo.AccessTokenMaxAge*60, "/", "localhost", false, true)
	ctx.SetCookie("refresh_token", tokens.RefreshToken, tokenInfo.RefreshTokenMaxAge*60, "/", "localhost", false, true)
	ctx.SetCookie("logged_in", "true", tokenInfo.AccessTokenMaxAge*60, "/", "localhost", false, false)

	userResponse := &dtos.UserResponse{
		ID:        user.ID,
		Username:  user.Username,
		Email:     user.Email,
		Role:      user.Role.String(),
		Verified:  user.Verified,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
	}

	// Return the response
	ctx.JSON(http.StatusOK, gin.H{
		"status": "success",
		"data": gin.H{
			"user":          userResponse,
			"access_token":  tokens.AccessToken,
			"refresh_token": tokens.RefreshToken,
			"expires_in":    tokens.ExpiresIn,
		},
	})

}

func (ac *AuthHandler) RefreshAccessTokenHandler(ctx *gin.Context) {

	message := "could not refresh access token"
	userRepo := repositories.NewUserRepository(ac.DB)
	cookie, err := ctx.Cookie("refresh_token")

	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusForbidden, gin.H{"status": "fail", "message": message})
		return
	}

	claims, err := utils.VerifyRefreshToken(cookie, ac.Config.RefreshTokenPublicKey)

	var refreshTokenRecord utils.RefreshToken
	result := ac.DB.Where("token = ? AND user_id = ? AND revoked = ? AND expires_at > ?",
		cookie, claims.UserID.String(), false, time.Now().In(time.UTC),
	).First(&refreshTokenRecord)

	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			ctx.AbortWithStatusJSON(http.StatusForbidden, gin.H{"status": "fail", "message": message, "error": "refresh token not found or invalid"})
			return
		}
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "failed to query refresh token", "error": result.Error})
		return
	}

	if refreshTokenRecord.Revoked {
		ctx.AbortWithStatusJSON(http.StatusForbidden, gin.H{"status": "fail", "message": message, "error": "refresh token has been revoked"})
		return
	}

	user, err := userRepo.FindByID(claims.UserID)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "failed to fetch user", "error": err.Error()})
		return
	}

	tokenInfo := utils.TokenConfig{
		AccessTokenSecret:   ac.Config.AccessTokenPrivateKey,
		AccessTokenDuration: time.Duration(ac.Config.AccessTokenMaxAge) * time.Minute,
		AccessTokenMaxAge:   ac.Config.AccessTokenMaxAge,
	}

	token, err := utils.GenerateJWT(*user, "access", tokenInfo.AccessTokenDuration, tokenInfo.AccessTokenSecret)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "Failed to generate tokens"})
		return
	}

	ctx.SetCookie("access_token", token, tokenInfo.AccessTokenMaxAge*60, "/", "localhost", false, true)
	ctx.SetCookie("logged_in", "true", tokenInfo.AccessTokenMaxAge*60, "/", "localhost", false, false)
	ctx.JSON(http.StatusOK, gin.H{
		"status": "success",
		"data": gin.H{
			"access_token": token,
		},
	})
}

func (ac *AuthHandler) Logout(ctx *gin.Context) {
	ctx.SetCookie("access_token", "", -1, "/", "localhost", false, true)
	ctx.SetCookie("refresh_token", "", -1, "/", "localhost", false, true)
	ctx.SetCookie("logged_in", "", -1, "/", "localhost", false, false)

	ctx.JSON(http.StatusOK, gin.H{"status": "success"})
}
