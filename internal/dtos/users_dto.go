package dtos

import (
	"time"

	"github.com/google/uuid"
)

type ValidationErrors struct {
	Field   string
	Message string
}
type FormData struct {
	Values map[string]string
	Errors map[string]string
}
type LoginRequest struct {
	LoginIndentifier string `form:"email" binding:"required"`
	Password         string `form:"password" binding:"required"`
}
type RegisterRequest struct {
	Username        string `form:"username" binding:"required"`
	Email           string `form:"email" binding:"required"`
	Password        string `form:"password" binding:"required,min=8"`
	PasswordConfirm string `form:"passwordconfirm" binding:"required"`
}

type UserResponse struct {
	ID        uuid.UUID `json:"id,omitempty"`
	Username  string    `json:"username,omitempty"`
	Email     string    `json:"email,omitempty"`
	Role      string    `json:"role,omitempty"`
	Verified  bool      `json:"verified,omitempty"`
	CreatedAt time.Time `json:"created_at,omitempty"`
	UpdatedAt time.Time `json:"updated_at,omitempty"`
}

func NewFormData() FormData {
	return FormData{
		Values: make(map[string]string),
		Errors: make(map[string]string),
	}
}
