package handlers

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	config "github.com/Mpinyaz/GinWebApp/config"
	"github.com/Mpinyaz/GinWebApp/internal/auth"
	"github.com/Mpinyaz/GinWebApp/internal/dtos"
	models "github.com/Mpinyaz/GinWebApp/internal/models/users"
	"github.com/Mpinyaz/GinWebApp/internal/repositories"
	utils "github.com/Mpinyaz/GinWebApp/internal/utils"
	"github.com/Mpinyaz/GinWebApp/internal/views/components"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"gorm.io/gorm"
)

type AuthHandler struct {
	DB     *gorm.DB
	Redis  *redis.Client
	Config *config.AppCfg
	CTX    *context.Context
}

func NewAuthHandler(DB *gorm.DB, Redis *redis.Client, Config *config.AppCfg, CTX *context.Context) AuthHandler {
	return AuthHandler{DB, Redis, Config, CTX}
}

func (ac *AuthHandler) RegisterHandler(ctx *gin.Context) {
	var req dtos.RegisterRequest
	formData := dtos.NewFormData()

	if err := ctx.ShouldBind(&req); err != nil {
		formData.Errors["form"] = []string{"Please fill in all required fields"}
		utils.Render(ctx, http.StatusUnprocessableEntity, components.RegisterForm(formData))
		return
	}

	formData.Values["email"] = req.Email
	formData.Values["username"] = req.Username

	dtos.ValidateRegInput(&req, &formData)

	if len(formData.Errors["email"]) > 0 ||
		len(formData.Errors["password"]) > 0 ||
		len(formData.Errors["username"]) > 0 ||
		len(formData.Errors["passwordconfirm"]) > 0 {
		utils.Render(ctx, http.StatusUnprocessableEntity, components.RegisterForm(formData))
		return
	}

	email := strings.ToLower(strings.TrimSpace(req.Email))
	username := strings.ToLower(strings.TrimSpace(req.Username))
	password := req.Password

	var existingUser models.User

	if result := ac.DB.Where("email = ?", email).First(&existingUser); result.RowsAffected > 0 {
		formData.Errors["email"] = []string{"Email address is already registered"}
		utils.Render(ctx, http.StatusConflict, components.RegisterForm(formData))
		return
	}

	if result := ac.DB.Where("username = ?", username).First(&existingUser); result.RowsAffected > 0 {
		formData.Errors["username"] = []string{"Username is already taken"}
		utils.Render(ctx, http.StatusConflict, components.RegisterForm(formData))
		return
	}

	hashedPassword, err := utils.HashPassword(password)
	if err != nil {
		formData.Errors["password"] = []string{"Unable to process registration at this moment"}
		utils.Render(ctx, http.StatusInternalServerError, components.RegisterForm(formData))
		return
	}

	now := time.Now().UTC()
	user := models.User{
		Username:  username,
		Email:     email,
		Password:  hashedPassword,
		Role:      models.RoleUser,
		Verified:  false,
		CreatedAt: now,
		UpdatedAt: now,
	}

	result := ac.DB.Create(&user)
	if result.Error != nil {
		if strings.Contains(result.Error.Error(), "duplicate key value violates unique") {
			if strings.Contains(result.Error.Error(), "email") {
				formData.Errors["email"] = []string{"Email address is already registered"}
			} else if strings.Contains(result.Error.Error(), "username") {
				formData.Errors["username"] = []string{"Username is already taken"}
			} else {
				formData.Errors["form"] = []string{"Account with this information already exists"}
			}
			utils.Render(ctx, http.StatusUnprocessableEntity, components.RegisterForm(formData))
		} else {
			formData.Errors["form"] = []string{"Unable to create account at this time"}
			utils.Render(ctx, http.StatusInternalServerError, components.RegisterForm(formData))
		}
		return
	}

	msg := fmt.Sprintf("Hey %s, you have been successfully registered", username)
	ctx.Header("HX-Redirect", "/login?success="+url.QueryEscape(msg))
	ctx.Status(http.StatusOK)
}

func (ac *AuthHandler) LoginHandler(ctx *gin.Context) {
	userRepo := repositories.NewUserRepository(ac.DB)
	authService := auth.NewAuthService(ac.DB, ac.Config, ac.Redis)
	var req dtos.LoginRequest
	formData := dtos.NewFormData()

	if err := ctx.ShouldBind(&req); err != nil {
		formData.Errors["form"] = []string{"Please fill in all required fields"}
		utils.Render(ctx, http.StatusUnprocessableEntity, components.LogInForm(formData))
		return
	}

	var user *models.User
	var err error

	if utils.IsValidEmail(req.LoginIndentifier) {
		user, err = userRepo.FindByEmail(req.LoginIndentifier)
	} else {
		user, err = userRepo.FindByUserame(req.LoginIndentifier)
	}

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			formData.Errors["form"] = []string{"Invalid email or Password"}
			utils.Render(ctx, http.StatusUnprocessableEntity, components.LogInForm(formData))

		} else {
			formData.Errors["form"] = []string{"Internal Error: " + err.Error()}
			utils.Render(ctx, http.StatusInternalServerError, components.LogInForm(formData))

		}
		return
	}

	if err := utils.VerifyPassword(user.Password, req.Password); err != nil {
		formData.Errors["form"] = []string{"Invalid email or Password"}
		utils.Render(ctx, http.StatusUnprocessableEntity, components.LogInForm(formData))
		return
	}

	userAgent := ctx.GetHeader("User-Agent")
	ipAddress := ctx.ClientIP()

	tokens, err := authService.GenerateTokens(*user, ipAddress, userAgent)
	if err != nil {
		formData.Errors["form"] = []string{"Internal Error: cannot login right now"}
		utils.Render(ctx, http.StatusUnprocessableEntity, components.LogInForm(formData))
		return
	}

	ctx.SetCookie("access_token", tokens.AccessToken, ac.Config.AccessTokenMaxAge*60*60, "/", "localhost", false, true)
	ctx.SetCookie("session_token", tokens.SessionToken, ac.Config.SessionTokenMaxAge*60*60, "/", "localhost", false, true)
	ctx.SetCookie("refresh_token", tokens.RefreshToken, ac.Config.RefreshTokenMaxAge*60*60, "/", "localhost", false, true)
	ctx.SetCookie("session_id", tokens.SessionID, ac.Config.SessionTokenMaxAge*60*60, "/", "localhost", false, false)
	ctx.SetCookie("logged_in", "true", ac.Config.SessionTokenMaxAge*60*60, "/", "localhost", false, false)

	ctx.Header("HX-Redirect", "/")
	ctx.Status(http.StatusOK)
}

func (ac *AuthHandler) Logout(ctx *gin.Context) {
	// Get session ID from cookie
	auth := auth.NewAuthService(ac.DB, ac.Config, ac.Redis)
	sessionID, err := ctx.Cookie("session_id")
	if err == nil && sessionID != "" {
		// Revoke the session using the auth service
		if err := auth.RevokeSession(*ac.CTX, sessionID); err != nil {
			// Log the error but continue with cookie removal
			ctx.Error(err)
		}
	}

	// Clear all cookies regardless of whether session revocation succeeded
	ctx.SetCookie("access_token", "", -1, "/", "localhost", false, true)
	ctx.SetCookie("session_token", "", -1, "/", "localhost", false, true)
	ctx.SetCookie("refresh_token", "", -1, "/", "localhost", false, true)
	ctx.SetCookie("session_id", "", -1, "/", "localhost", false, true)
	ctx.SetCookie("logged_in", "", -1, "/", "localhost", false, false)

	ctx.Header("HX-Redirect", "/")
	ctx.Status(http.StatusOK)
}

func (ac *AuthHandler) RefreshTokensHandler(ctx *gin.Context) {
	userRepo := repositories.NewUserRepository(ac.DB)
	authService := auth.NewAuthService(ac.DB, ac.Config, ac.Redis)

	// Get refresh token from cookie
	refreshToken, err := ctx.Cookie("refresh_token")
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusForbidden, gin.H{"status": "fail", "message": "refresh token not found"})
		return
	}

	// Verify refresh token
	claims, refreshTokenRecord, err := authService.VerifyRefreshToken(refreshToken, ac.Config.RefreshTokenPublicKey)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusForbidden, gin.H{"status": "fail", "message": "invalid refresh token: " + err.Error()})
		return
	}

	// Get user
	user, err := userRepo.FindByID(claims.UserID)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "failed to fetch user"})
		return
	}

	// Revoke the old refresh token
	if err := ac.DB.Model(&auth.RefreshToken{}).Where("id = ?", refreshTokenRecord.ID).Update("revoked", true).Error; err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "failed to revoke old refresh token"})
		return
	}

	// Get device info from headers
	userAgent := ctx.GetHeader("User-Agent")
	ipAddress := ctx.ClientIP()

	// Generate new tokens
	tokens, err := authService.GenerateTokens(*user, ipAddress, userAgent)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "Failed to generate new tokens: " + err.Error()})
		return
	}

	// Set new cookies
	ctx.SetCookie("access_token", tokens.AccessToken, ac.Config.AccessTokenMaxAge*60*60, "/", "localhost", false, true)
	ctx.SetCookie("session_token", tokens.SessionToken, ac.Config.SessionTokenMaxAge*60*60, "/", "localhost", false, true)
	ctx.SetCookie("refresh_token", tokens.RefreshToken, ac.Config.RefreshTokenMaxAge*60*60, "/", "localhost", false, true)
	ctx.SetCookie("session_id", tokens.SessionID, ac.Config.SessionTokenMaxAge*60*60, "/", "localhost", false, true)
	ctx.SetCookie("logged_in", "true", ac.Config.SessionTokenMaxAge*60*60, "/", "localhost", false, false)

	// Return the new tokens
	ctx.JSON(http.StatusOK, gin.H{
		"status": "success",
		"data": gin.H{
			"access_token":  tokens.AccessToken,
			"session_token": tokens.SessionToken,
			"refresh_token": tokens.RefreshToken,
			"session_id":    tokens.SessionID,
			"expires_in":    tokens.ExpiresIn,
		},
	})
}
