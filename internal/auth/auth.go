package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Mpinyaz/GinWebApp/config"
	models "github.com/Mpinyaz/GinWebApp/internal/models/users"
	"github.com/go-redis/redis/v8"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type AuthService struct {
	DB        *gorm.DB
	RedisConn *redis.Client
	TokenCfg  *TokenConfig
}

func NewAuthService(db *gorm.DB, cfg *config.AppCfg, redis *redis.Client) *AuthService {
	tokenInfo := TokenConfig{
		AccessTokenSecret:    cfg.AccessTokenPrivateKey,
		AccessTokenDuration:  time.Duration(cfg.AccessTokenMaxAge) * time.Hour,
		SessionTokenSecret:   cfg.SessionTokenPrivateKey,
		SessionTokenDuration: time.Duration(cfg.SessionTokenMaxAge) * time.Hour,
		RefreshTokenSecret:   cfg.RefreshTokenPrivateKey,
		RefreshTokenDuration: time.Duration(cfg.RefreshTokenMaxAge) * time.Hour,
		AccessTokenMaxAge:    cfg.AccessTokenMaxAge,
		SessionTokenMaxAge:   cfg.SessionTokenMaxAge,
		RefreshTokenMaxAge:   cfg.RefreshTokenMaxAge,
	}

	return &AuthService{
		DB:        db,
		RedisConn: redis,
		TokenCfg:  &tokenInfo,
	}
}

type TokenType int

const (
	TokenTypeAccess TokenType = iota
	TokenTypeRefresh
	TokenTypeSession
)

func (r TokenType) String() string {
	switch r {
	case TokenTypeAccess:
		return "access"
	case TokenTypeRefresh:
		return "refresh"
	case TokenTypeSession:
		return "session"
	default:
		return "unknown"
	}
}

type JWTClaims struct {
	UserID    uuid.UUID   `json:"user_id"`
	Username  string      `json:"username"`
	Role      models.Role `json:"role"`
	TokenType TokenType   `json:"token_type"`
	jwt.RegisteredClaims
}

type AccessTokenClaims struct {
	JWTClaims
}

type RefreshTokenClaims struct {
	JWTClaims
}

type SessionTokenClaims struct {
	JWTClaims
	SessionID string `json:"session"`
}

type TokenConfig struct {
	AccessTokenDuration  time.Duration
	AccessTokenSecret    string
	RefreshTokenDuration time.Duration
	RefreshTokenSecret   string
	SessionTokenDuration time.Duration
	SessionTokenSecret   string
	AccessTokenMaxAge    int
	RefreshTokenMaxAge   int
	SessionTokenMaxAge   int
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	SessionToken string `json:"session_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	SessionID    string `json:"session_id"`
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

type Session struct {
	gorm.Model
	ID           string    `gorm:"primaryKey;type:uuid"`
	UserID       uuid.UUID `gorm:"not null;index"`
	SessionToken string    `gorm:"not null;index"`
	LastActive   time.Time `gorm:"not null"`
	ExpiresAt    time.Time `gorm:"not null;index"`
	IsActive     bool      `gorm:"default:true;index"`
	IPAddress    string    `gorm:"type:varchar(45)"`
	UserAgent    string    `gorm:"type:text"`
}

type RefreshToken struct {
	gorm.Model
	Token     string    `gorm:"not null;uniqueIndex"`
	UserID    uuid.UUID `gorm:"not null;index"`
	SessionID string    `gorm:"not null;index"`
	ExpiresAt time.Time `gorm:"not null;index"`
	Revoked   bool      `gorm:"default:false;index"`
}

type BlacklistedToken struct {
	gorm.Model
	Token     string    `gorm:"not null;uniqueIndex"`
	TokenType TokenType `gorm:"not null"`
	ExpiresAt time.Time `gorm:"not null;index"`
}

func (as *AuthService) GenerateAccessToken(user models.User) (string, error) {
	expiration := as.TokenCfg.AccessTokenDuration
	secretKey := as.TokenCfg.AccessTokenSecret

	decodedPrivateKey, err := base64.StdEncoding.DecodeString(secretKey)
	if err != nil {
		return "", fmt.Errorf("could not decode key: %w", err)
	}

	key, err := jwt.ParseRSAPrivateKeyFromPEM(decodedPrivateKey)
	if err != nil {
		return "", fmt.Errorf("create: parse key: %w", err)
	}

	now := time.Now().UTC()
	claims := AccessTokenClaims{
		JWTClaims: JWTClaims{
			UserID:    user.ID,
			Username:  user.Username,
			Role:      user.Role,
			TokenType: TokenTypeAccess,
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(now.Add(expiration)),
				Subject:   user.ID.String(),
				Audience:  jwt.ClaimStrings{},
				NotBefore: jwt.NewNumericDate(now),
				IssuedAt:  jwt.NewNumericDate(now),
			},
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signedToken, err := token.SignedString(key)
	if err != nil {
		return "", fmt.Errorf("failed to sign access token: %w", err)
	}

	return signedToken, nil
}

func (as *AuthService) GenerateSessionToken(user models.User, sessionID string) (string, error) {
	expiration := as.TokenCfg.SessionTokenDuration
	secretKey := as.TokenCfg.SessionTokenSecret

	decodedPrivateKey, err := base64.StdEncoding.DecodeString(secretKey)
	if err != nil {
		return "", fmt.Errorf("could not decode key: %w", err)
	}

	key, err := jwt.ParseRSAPrivateKeyFromPEM(decodedPrivateKey)
	if err != nil {
		return "", fmt.Errorf("create: parse key: %w", err)
	}

	now := time.Now().UTC()
	claims := SessionTokenClaims{
		JWTClaims: JWTClaims{
			UserID:    user.ID,
			Username:  user.Username,
			Role:      user.Role,
			TokenType: TokenTypeSession,
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(now.Add(expiration)),
				Subject:   user.ID.String(),
				Audience:  jwt.ClaimStrings{},
				NotBefore: jwt.NewNumericDate(now),
				IssuedAt:  jwt.NewNumericDate(now),
			},
		},
		SessionID: sessionID,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signedToken, err := token.SignedString(key)
	if err != nil {
		return "", fmt.Errorf("failed to sign session token: %w", err)
	}

	return signedToken, nil
}

func (as *AuthService) GenerateRefreshToken(user models.User) (string, error) {
	expiration := as.TokenCfg.RefreshTokenDuration
	secretKey := as.TokenCfg.RefreshTokenSecret

	decodedPrivateKey, err := base64.StdEncoding.DecodeString(secretKey)
	if err != nil {
		return "", fmt.Errorf("could not decode key: %w", err)
	}

	key, err := jwt.ParseRSAPrivateKeyFromPEM(decodedPrivateKey)
	if err != nil {
		return "", fmt.Errorf("create: parse key: %w", err)
	}

	now := time.Now().UTC()
	claims := RefreshTokenClaims{
		JWTClaims: JWTClaims{
			UserID:    user.ID,
			Username:  user.Username,
			Role:      user.Role,
			TokenType: TokenTypeRefresh,
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(now.Add(expiration)),
				Subject:   user.ID.String(),
				Audience:  jwt.ClaimStrings{},
				NotBefore: jwt.NewNumericDate(now),
				IssuedAt:  jwt.NewNumericDate(now),
			},
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signedToken, err := token.SignedString(key)
	if err != nil {
		return "", fmt.Errorf("failed to sign refresh token: %w", err)
	}

	return signedToken, nil
}

func (as *AuthService) SaveRefreshToken(refreshToken string, userID uuid.UUID, sessionID string) error {
	expiration := as.TokenCfg.RefreshTokenDuration
	refreshTokenRecord := RefreshToken{
		Token:     refreshToken,
		UserID:    userID,
		SessionID: sessionID,
		ExpiresAt: time.Now().Add(expiration).UTC(),
		Revoked:   false,
	}

	return as.DB.Create(&refreshTokenRecord).Error
}

func (as *AuthService) CreateSession(ctx context.Context, user models.User, ipAddress, userAgent string) (*Session, error) {
	sessionID := uuid.New().String()
	session := Session{
		ID:         sessionID,
		UserID:     user.ID,
		LastActive: time.Now().UTC(),
		ExpiresAt:  time.Now().Add(as.TokenCfg.SessionTokenDuration).UTC(),
		IsActive:   true,
		IPAddress:  ipAddress,
		UserAgent:  userAgent,
	}

	sessionJSON, err := json.Marshal(session)
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	key := fmt.Sprintf("session:%s", sessionID)
	if err := as.RedisConn.Set(ctx, key, sessionJSON, as.TokenCfg.SessionTokenDuration).Err(); err != nil {
		return nil, fmt.Errorf("failed to store session in Redis: %w", err)
	}

	userSessionKey := fmt.Sprintf("user:%s:sessions", user.ID.String())
	if err := as.RedisConn.SAdd(ctx, userSessionKey, sessionID).Err(); err != nil {
		return nil, fmt.Errorf("failed to store session in user session: %w", err)
	}
	return &session, nil
}

func (as *AuthService) GetSession(ctx context.Context, sessionID string) (*Session, error) {
	key := fmt.Sprintf("session:%s", sessionID)
	sessionJSON, err := as.RedisConn.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, fmt.Errorf("session not found")
		}
		return nil, fmt.Errorf("failed to get session from Redis: %w", err)
	}

	var session Session
	if err := json.Unmarshal([]byte(sessionJSON), &session); err != nil {
		return nil, fmt.Errorf("failed to unmarshal session: %w", err)
	}

	if !session.IsActive || time.Now().After(session.ExpiresAt) {
		return nil, fmt.Errorf("session expired or inactive")
	}

	return &session, nil
}

func (as *AuthService) UpdateSessionActivity(ctx context.Context, sessionID string) error {
	session, err := as.GetSession(ctx, sessionID)
	if err != nil {
		return err
	}

	session.LastActive = time.Now().UTC()
	sessionJSON, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("failed to marshal updated session: %w", err)
	}

	key := fmt.Sprintf("session:%s", sessionID)
	remaining := time.Until(session.ExpiresAt)
	if remaining <= 0 {
		return fmt.Errorf("session already expired")
	}

	if err := as.RedisConn.Set(ctx, key, sessionJSON, remaining).Err(); err != nil {
		return fmt.Errorf("failed to update session in Redis: %w", err)
	}

	return nil
}

func (as *AuthService) RevokeSession(ctx context.Context, sessionID string) error {
	session, err := as.GetSession(ctx, sessionID)
	if err != nil {
		return err
	}

	session.IsActive = false
	sessionJSON, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("failed to marshal revoked session: %w", err)
	}

	key := fmt.Sprintf("session:%s", sessionID)
	if err := as.RedisConn.Set(ctx, key, sessionJSON, time.Hour).Err(); err != nil {
		return fmt.Errorf("failed to revoke session in Redis: %w", err)
	}

	tx := as.DB.Begin()
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	if err := tx.Model(&RefreshToken{}).Where("session_id = ? AND revoked = ?", sessionID, false).Update("revoked", true).Error; err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to revoke refresh tokens: %w", err)
	}

	return tx.Commit().Error
}

func (as *AuthService) RevokeAllUserSessions(ctx context.Context, userID uuid.UUID) error {
	userSessionsKey := fmt.Sprintf("user:%s:sessions", userID.String())

	sessionIDs, err := as.RedisConn.SMembers(ctx, userSessionsKey).Result()
	if err != nil {
		return fmt.Errorf("failed to get user sessions: %w", err)
	}

	for _, sessionID := range sessionIDs {
		if err := as.RevokeSession(ctx, sessionID); err != nil {
			fmt.Printf("Error revoking session %s: %v\n", sessionID, err)
		}
	}

	if err := as.RedisConn.Del(ctx, userSessionsKey).Err(); err != nil {
		return fmt.Errorf("failed to remove user sessions set: %w", err)
	}

	tx := as.DB.Begin()
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	// Mark all refresh tokens for this user as revoked
	if err := tx.Model(&RefreshToken{}).Where("user_id = ? AND revoked = ?", userID, false).Update("revoked", true).Error; err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to revoke user refresh tokens: %w", err)
	}

	return tx.Commit().Error
}

func (as *AuthService) GenerateTokens(user models.User, ipAddress string, userAgent string) (TokenResponse, error) {
	session, err := as.CreateSession(context.Background(), user, ipAddress, userAgent)
	if err != nil {
		return TokenResponse{}, err
	}

	accessToken, err := as.GenerateAccessToken(user)
	if err != nil {
		return TokenResponse{}, fmt.Errorf("failed to generate access token: %w", err)
	}

	sessionToken, err := as.GenerateSessionToken(user, session.ID)
	if err != nil {
		return TokenResponse{}, fmt.Errorf("failed to generate session token: %w", err)
	}

	refreshToken, err := as.GenerateRefreshToken(user)
	if err != nil {
		return TokenResponse{}, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	if err := as.SaveRefreshToken(refreshToken, user.ID, session.ID); err != nil {
		return TokenResponse{}, fmt.Errorf("failed to store new refresh token: %w", err)
	}

	return TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		SessionToken: sessionToken,
		ExpiresIn:    int(as.TokenCfg.AccessTokenDuration.Seconds()),
	}, nil
}

func (as *AuthService) VerifyAccessToken(tokenString string, publicKey string) (*AccessTokenClaims, error) {
	decodedPublicKey, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		return nil, fmt.Errorf("could not decode public key: %w", err)
	}

	key, err := jwt.ParseRSAPublicKeyFromPEM(decodedPublicKey)
	if err != nil {
		return nil, fmt.Errorf("could not parse public key: %w", err)
	}

	token, err := jwt.ParseWithClaims(tokenString, &AccessTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return key, nil
	})
	if err != nil {
		return nil, fmt.Errorf("invalid access token: %w", err)
	}

	claims, ok := token.Claims.(*AccessTokenClaims)
	if !ok || !token.Valid || claims.TokenType != TokenTypeAccess {
		return nil, fmt.Errorf("invalid or mismatched token type: expected access token")
	}

	// Check expiration explicitly
	if claims.ExpiresAt != nil && !claims.ExpiresAt.Time.After(time.Now().UTC()) {
		return nil, fmt.Errorf("access token has expired")
	}

	return claims, nil
}

// RefreshAccessToken refreshes only the access token while maintaining the existing session
func (as *AuthService) RefreshAccessToken(ctx context.Context, sessionID string, user models.User) (string, error) {
	// Check if the session is still active
	_, err := as.GetSession(ctx, sessionID)
	if err != nil {
		return "", fmt.Errorf("session not found or expired: %w", err)
	}

	// Update last active time
	if err := as.UpdateSessionActivity(ctx, sessionID); err != nil {
		return "", fmt.Errorf("failed to update session activity: %w", err)
	}

	// Generate new access token
	accessToken, err := as.GenerateAccessToken(user)
	if err != nil {
		return "", fmt.Errorf("failed to generate new access token: %w", err)
	}

	return accessToken, nil
}

func (as *AuthService) verifyRefreshTokenClaims(refreshTokenString string, publicKey string) (*RefreshTokenClaims, error) {
	decodedPublicKey, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		return nil, fmt.Errorf("could not decode public key: %w", err)
	}

	key, err := jwt.ParseRSAPublicKeyFromPEM(decodedPublicKey)
	if err != nil {
		return nil, fmt.Errorf("could not parse public key: %w", err)
	}

	token, err := jwt.ParseWithClaims(refreshTokenString, &RefreshTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return key, nil
	})
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token: %w", err)
	}

	claims, ok := token.Claims.(*RefreshTokenClaims)
	if !ok || !token.Valid || claims.TokenType != TokenTypeRefresh {
		return nil, fmt.Errorf("invalid or mismatched token type: expected refresh token")
	}

	// Check expiration explicitly
	if claims.ExpiresAt != nil && !claims.ExpiresAt.Time.After(time.Now().UTC()) {
		return nil, fmt.Errorf("refresh token has expired")
	}

	return claims, nil
}

func (as *AuthService) VerifyRefreshToken(refreshTokenString string, publicKey string) (*RefreshTokenClaims, *RefreshToken, error) {
	claims, err := as.verifyRefreshTokenClaims(refreshTokenString, publicKey)
	if err != nil {
		return nil, nil, err
	}

	// Check if the refresh token is still valid in the database
	var refreshTokenRecord RefreshToken
	if err := as.DB.Where("token = ? AND revoked = ? AND expires_at > ?", refreshTokenString, false, time.Now().UTC()).First(&refreshTokenRecord).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil, fmt.Errorf("refresh token revoked or expired")
		}
		return nil, nil, fmt.Errorf("database error while verifying refresh token: %w", err)
	}

	return claims, &refreshTokenRecord, nil
}
