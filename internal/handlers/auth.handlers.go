package handlers

import (
	"context"
	"errors"
	"net/http"
	"regexp"
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
		formData.Errors["form"] = "Please fill in all required fields"
		ctx.Header("Content-Type", "text/html; charset=utf-8")
		ctx.Status(http.StatusUnprocessableEntity) // Set status before rendering
		components.RegisterForm(formData).Render(ctx.Request.Context(), ctx.Writer)
		return
	}

	// Always populate form values for error cases
	formData.Values["email"] = req.Email
	formData.Values["username"] = req.Username

	email := strings.ToLower(strings.TrimSpace(req.Email))
	username := strings.ToLower(strings.TrimSpace(req.Username))
	password := req.Password

	// Check for existing email
	var existingUser models.User
	if result := ac.DB.Where("email = ?", email).First(&existingUser); result.RowsAffected > 0 {
		formData.Errors["email"] = "Email address is already registered"
		ctx.Header("Content-Type", "text/html; charset=utf-8")
		ctx.Status(http.StatusUnprocessableEntity) // Use 422 for validation errors
		components.RegisterForm(formData).Render(ctx.Request.Context(), ctx.Writer)
		return
	}

	// Check for existing username
	if result := ac.DB.Where("username = ?", username).First(&existingUser); result.RowsAffected > 0 {
		formData.Errors["username"] = "Username is already taken" // Fixed field name (was "Username")
		ctx.Header("Content-Type", "text/html; charset=utf-8")
		ctx.Status(http.StatusUnprocessableEntity) // Use 422 for validation errors
		components.RegisterForm(formData).Render(ctx.Request.Context(), ctx.Writer)
		return
	}

	// Hash password
	hashedPassword, err := utils.HashPassword(password)
	if err != nil {
		formData.Errors["password"] = "Unable to process registration at this moment"
		ctx.Header("Content-Type", "text/html; charset=utf-8")
		ctx.Status(http.StatusInternalServerError)
		components.RegisterForm(formData).Render(ctx.Request.Context(), ctx.Writer)
		return
	}

	// Create user
	now := time.Now().In(time.UTC)
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
			// Handle race condition where user was created between our checks
			if strings.Contains(result.Error.Error(), "email") {
				formData.Errors["email"] = "Email address is already registered"
			} else if strings.Contains(result.Error.Error(), "username") {
				formData.Errors["username"] = "Username is already taken"
			} else {
				formData.Errors["form"] = "Account with this information already exists"
			}
			ctx.Status(http.StatusUnprocessableEntity)
		} else {
			formData.Errors["form"] = "Unable to create account at this time"
			ctx.Status(http.StatusInternalServerError)
		}
		ctx.Header("Content-Type", "text/html; charset=utf-8")
		components.RegisterForm(formData).Render(ctx.Request.Context(), ctx.Writer)
		return
	}

	// Success - redirect to login
	ctx.Redirect(http.StatusSeeOther, "/login")
}

func (ac *AuthHandler) LoginHandler(ctx *gin.Context) {
	userRepo := repositories.NewUserRepository(ac.DB)
	authService := auth.NewAuthService(ac.DB, ac.Config, ac.Redis)
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
		user, err = userRepo.FindByUserame(payload.LoginIndentifier)
	}

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			ctx.JSON(http.StatusBadRequest, gin.H{"status": "fail", "message": "Invalid email or Password"})
		} else {
			ctx.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "Database error: " + err.Error()})
		}
		return
	}

	if err := utils.VerifyPassword(user.Password, payload.Password); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"status": "fail", "message": "Invalid email or Password"})
		return
	}

	// Get device info from headers
	userAgent := ctx.GetHeader("User-Agent")
	ipAddress := ctx.ClientIP()

	tokens, err := authService.GenerateTokens(*user, ipAddress, userAgent)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "Failed to generate tokens: " + err.Error()})
		return
	}

	// Set cookies for the tokens
	ctx.SetCookie("access_token", tokens.AccessToken, ac.Config.AccessTokenMaxAge*60*60, "/", "localhost", false, true)
	ctx.SetCookie("session_token", tokens.SessionToken, ac.Config.SessionTokenMaxAge*60*60, "/", "localhost", false, true)
	ctx.SetCookie("refresh_token", tokens.RefreshToken, ac.Config.RefreshTokenMaxAge*60*60, "/", "localhost", false, true)
	ctx.SetCookie("logged_in", "true", ac.Config.SessionTokenMaxAge*60*60, "/", "localhost", false, false)

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
			"session_token": tokens.SessionToken,
			"refresh_token": tokens.RefreshToken,
			"session_id":    tokens.SessionID,
			"expires_in":    tokens.ExpiresIn,
		},
	})
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

	ctx.JSON(http.StatusOK, gin.H{"status": "success"})
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
