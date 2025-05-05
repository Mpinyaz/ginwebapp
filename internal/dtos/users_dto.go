package dtos

import (
	models "github.com/Mpinyaz/GinWebApp/internal/models/users"
	"github.com/google/uuid"
	"time"
)

type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type RegisterRequest struct {
	Username        string `json:"username" binding:"required"`
	Email           string `json:"email" binding:"required"`
	Password        string `json:"password" binding:"required,min=8"`
	PasswordConfirm string `json:"passwordConfirm" binding:"required"`
}

type UserResponse struct {
	ID        uuid.UUID   `json:"id,omitempty"`
	Username  string      `json:"username,omitempty"`
	Email     string      `json:"email,omitempty"`
	Role      models.Role `json:"role,omitempty"`
	Verified  bool        `json:"verified"`
	CreatedAt time.Time   `json:"created_at"`
	UpdatedAt time.Time   `json:"updated_at"`
}
