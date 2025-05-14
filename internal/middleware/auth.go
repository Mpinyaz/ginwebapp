package auth

import (
	"encoding/base64"
	"errors"
	"fmt"
	models "github.com/Mpinyaz/GinWebApp/internal/models/users"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"time"
)

type JWTClaims struct {
	UserID    uuid.UUID   `json:"user_id"`
	Username  string      `json:"username"`
	Role      models.Role `json:"role"`
	TokenType string      `json:"token_type"`
	jwt.RegisteredClaims
}
type TokenConfig struct {
	AccessTokenDuration  time.Duration
	AccessTokenSecret    string
	RefreshTokenDuration time.Duration
	RefreshTokenSecret   string
	AccessTokenMaxAge    int
	RefreshTokenMaxAge   int
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
	UserID    uuid.UUID `gorm:"not null;index"`
	ExpiresAt time.Time `gorm:"not null;index"`
	Revoked   bool      `gorm:"default:false;index"`
}

type BlacklistedToken struct {
	gorm.Model
	Token     string    `gorm:"not null;uniqueIndex"`
	ExpiresAt time.Time `gorm:"not null;index"`
}

func GenerateJWT(user models.User, tokenType string, expiration time.Duration, secretKey string) (string, error) {
	decodedPrivateKey, err := base64.StdEncoding.DecodeString(secretKey)
	if err != nil {
		return "", fmt.Errorf("could not decode key: %w", err)
	}

	key, err := jwt.ParseRSAPrivateKeyFromPEM(decodedPrivateKey)

	if err != nil {
		return "", fmt.Errorf("create: parse key: %w", err)
	}

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
	signedToken, err := token.SignedString(key)

	if err != nil {
		return "", fmt.Errorf("failed to sign %s token: %w", tokenType, err)
	}

	return signedToken, nil
}

func GenerateTokens(user models.User, db *gorm.DB, tokenKeys TokenConfig) (TokenResponse, error) {
	accessToken, err := GenerateJWT(user, "access", tokenKeys.AccessTokenDuration, tokenKeys.AccessTokenSecret)
	if err != nil {
		return TokenResponse{}, fmt.Errorf("failed to generate access token: %w", err)
	}

	refreshToken, err := GenerateJWT(user, "refresh", tokenKeys.RefreshTokenDuration, tokenKeys.RefreshTokenSecret)
	if err != nil {
		return TokenResponse{}, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	if err := db.Model(&RefreshToken{}).Where("user_id = ? AND revoked = ?", user.ID, false).Update("revoked", true).Error; err != nil {
		return TokenResponse{}, fmt.Errorf("failed to revoke previous refresh tokens: %w", err)
	}

	tokenRecord := RefreshToken{
		UserID:    user.ID,
		Token:     refreshToken,
		ExpiresAt: time.Now().Add(tokenKeys.RefreshTokenDuration).In(time.UTC),
		Revoked:   false,
	}

	if err := db.Create(&tokenRecord).Error; err != nil {
		return TokenResponse{}, fmt.Errorf("failed to store new refresh token: %w", err)
	}

	return TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int(tokenKeys.AccessTokenDuration.Seconds()),
	}, nil
}

func VerifyToken(tokenString string, tokenType string, publicKey string) (*JWTClaims, error) {
	decodedPublicKey, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		return nil, fmt.Errorf("could not decode public key: %w", err)
	}

	key, err := jwt.ParseRSAPublicKeyFromPEM(decodedPublicKey)
	if err != nil {
		return nil, fmt.Errorf("could not parse public key: %w", err)
	}

	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return key, nil
	})

	if err != nil {
		return nil, fmt.Errorf("invalid %s token: %w", tokenType, err)
	}

	claims, ok := token.Claims.(*JWTClaims)
	if !ok || !token.Valid || claims.TokenType != tokenType {
		return nil, fmt.Errorf("invalid or mismatched %s token", tokenType)
	}

	// Check expiration explicitly. The jwt library checks it, but we want to be sure.
	if claims.ExpiresAt != nil && !claims.ExpiresAt.Time.After(time.Now().In(time.UTC)) {
		return nil, fmt.Errorf("%s token has expired", tokenType)
	}

	return claims, nil
}

func VerifyRefreshToken(refreshTokenString string, publicKey string) (*JWTClaims, error) {
	claims, err := VerifyToken(refreshTokenString, "refresh", publicKey)
	if err != nil {
		return nil, err
	}

	return claims, nil
}
