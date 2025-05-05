package auth

import (
	"errors"
	"fmt"
	models "github.com/Mpinyaz/GinWebApp/internal/models/users"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"time"
)

const (
	jwtCookieName        = "auth_token"
	accessTokenDuration  = 24 * time.Hour * 7
	refreshTokenDuration = 24 * time.Hour * 30
	cookieDomain         = "localhost"
	cookieSecure         = false
	cookieHTTPOnly       = true
	cookiePath           = "/"
	accessTokenSecret    = "access_secret_key_change_in_production"
	refreshTokenSecret   = "refresh_secret_key_change_in_production"
)

type JWTClaims struct {
	UserID    uuid.UUID   `json:"user_id"`
	Username  string      `json:"username"`
	Role      models.Role `json:"role"`
	TokenType string      `json:"token_type"`
	jwt.RegisteredClaims
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
}
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

type RefreshToken struct {
	gorm.Model
	Token     string    `gorm:"not null;uniqueIndex"`
	UserID    string    `gorm:"not null;index"`
	ExpiresAt time.Time `gorm:"not null;index"`
	Revoked   bool      `gorm:"default:false;index"`
}

type BlacklistedToken struct {
	gorm.Model
	Token     string    `gorm:"not null;uniqueIndex"`
	ExpiresAt time.Time `gorm:"not null;index"`
}

func generateJWT(user models.User, tokenType string, expiration time.Duration, secretKey string) (string, error) {
	claims := JWTClaims{
		UserID:    user.ID,
		Username:  user.Username,
		Role:      user.Role,
		TokenType: tokenType,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(expiration).In(time.UTC)), // Use UTC consistently
			Subject:   user.ID.String(),
			Audience:  jwt.ClaimStrings{},
			NotBefore: jwt.NewNumericDate(time.Now().In(time.UTC)),
			IssuedAt:  jwt.NewNumericDate(time.Now().In(time.UTC)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signedToken, err := token.SignedString([]byte(secretKey))

	if err != nil {
		return "", fmt.Errorf("failed to sign %s token: %w", tokenType, err)
	}

	return signedToken, nil
}

func generateAccessToken(user models.User) (string, error) {
	return generateJWT(user, "access", accessTokenDuration, accessTokenSecret)
}

func generateRefreshToken(user models.User) (string, error) {
	return generateJWT(user, "refresh", refreshTokenDuration, refreshTokenSecret)
}

func GenerateTokens(user models.User, db *gorm.DB) (TokenResponse, error) {
	accessToken, err := generateAccessToken(user)
	if err != nil {
		return TokenResponse{}, fmt.Errorf("failed to generate access token: %w", err)
	}

	refreshToken, err := generateRefreshToken(user)
	if err != nil {
		return TokenResponse{}, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	// Revoke existing refresh tokens for the user
	if err := db.Model(&RefreshToken{}).Where("user_id = ? AND revoked = ?", user.ID, false).Update("revoked", true).Error; err != nil {
		return TokenResponse{}, fmt.Errorf("failed to revoke previous refresh tokens: %w", err)
	}

	tokenRecord := RefreshToken{
		UserID:    user.ID.String(),
		Token:     refreshToken,
		ExpiresAt: time.Now().Add(refreshTokenDuration).In(time.UTC), // Use UTC
		Revoked:   false,
	}

	if err := db.Create(&tokenRecord).Error; err != nil {
		return TokenResponse{}, fmt.Errorf("failed to store new refresh token: %w", err)
	}

	return TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int(accessTokenDuration.Seconds()),
	}, nil
}

// VerifyToken verifies the token signature and expiration.  It does NOT check the database.
func VerifyToken(tokenString string, tokenType string, secretKey string) (*JWTClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secretKey), nil
	})

	if err != nil {
		return nil, fmt.Errorf("invalid %s token: %w", tokenType, err)
	}

	claims, ok := token.Claims.(*JWTClaims)
	if !ok || !token.Valid || claims.TokenType != tokenType {
		return nil, fmt.Errorf("invalid or mismatched %s token", tokenType)
	}

	// Check expiration explicitly.  The jwt library checks it, but we want to be sure.
	if claims.ExpiresAt != nil && !claims.ExpiresAt.Time.After(time.Now().In(time.UTC)) {
		return nil, fmt.Errorf("%s token has expired", tokenType)
	}

	return claims, nil
}

func VerifyRefreshToken(db *gorm.DB, refreshTokenString string) (*JWTClaims, error) {
	claims, err := VerifyToken(refreshTokenString, "refresh", refreshTokenSecret)
	if err != nil {
		return nil, err //  VerifyToken already wraps the error with context
	}

	var refreshTokenRecord RefreshToken
	if err := db.Where("token = ? AND user_id = ? AND revoked = ? AND expires_at > ?",
		refreshTokenString, claims.UserID.String(), false, time.Now().In(time.UTC),
	).First(&refreshTokenRecord).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("refresh token not found or invalid")
		}
		return nil, fmt.Errorf("failed to query refresh token: %w", err)
	}

	if refreshTokenRecord.Revoked {
		return nil, fmt.Errorf("refresh token has been revoked")
	}

	if refreshTokenRecord.ExpiresAt.Before(time.Now().In(time.UTC)) {
		return nil, fmt.Errorf("refresh token has expired")
	}

	return claims, nil
}
