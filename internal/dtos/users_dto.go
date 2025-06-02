package dtos

import (
	"strings"
	"time"

	"github.com/Mpinyaz/GinWebApp/internal/utils"
	"github.com/google/uuid"
)

type ValidationErrors struct {
	Field   string
	Message string
}
type FormData struct {
	Values map[string]string
	Errors map[string][]string
}
type LoginRequest struct {
	LoginIndentifier string `form:"email" binding:"required"`
	Password         string `form:"password" binding:"required"`
}
type RegisterRequest struct {
	Username        string `form:"username" binding:"required"`
	Email           string `form:"email" binding:"required"`
	Password        string `form:"password" binding:"required"`
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
		Errors: make(map[string][]string),
	}
}

func ValidateRegInput(req *RegisterRequest, formData *FormData) {
	// Initialize error slices if they don't exist
	if formData.Errors["email"] == nil {
		formData.Errors["email"] = make([]string, 0)
	}
	if formData.Errors["username"] == nil {
		formData.Errors["username"] = make([]string, 0)
	}
	if formData.Errors["password"] == nil {
		formData.Errors["password"] = make([]string, 0)
	}
	if formData.Errors["passwordconfirm"] == nil {
		formData.Errors["passwordconfirm"] = make([]string, 0)
	}
	if !utils.IsValidEmail(req.Email) {
		formData.Errors["email"] = append(formData.Errors["email"], "Please enter a valid email address")
	}

	if len([]rune(strings.TrimSpace(req.Username))) < 3 {
		formData.Errors["username"] = append(formData.Errors["username"], "Username must be atleast 3 characters long")
	}
	if len([]rune(strings.TrimSpace(req.Username))) > 30 {
		formData.Errors["username"] = append(formData.Errors["username"], "Username must be less than 30 characters long")
	}
	if req.Password != req.PasswordConfirm {
		formData.Errors["passwordconfirm"] = append(formData.Errors["passwordconfirm"], "Passwords do not match")
	}

	if len([]rune(req.Password)) < 8 {
		formData.Errors["password"] = append(formData.Errors["password"], "Password must be at least 8 characters long")
	}
	if !utils.IsStrongPassword(req.Password) {
		formData.Errors["password"] = append(formData.Errors["password"], "Password must contain uppercase,lowercase and number")
	}
}
