package models

import (
	"github.com/google/uuid"
	"time"
)

type Role int

const (
	RoleAdmin Role = iota
	RoleUser
	RoleGuest
)

func (r Role) String() string {
	switch r {
	case RoleAdmin:
		return "admin"
	case RoleUser:
		return "user"
	case RoleGuest:
		return "guest"
	default:
		return "unknown"
	}
}

type User struct {
	ID        uuid.UUID `json:"id" gorm:"type:uuid;default:uuid_generate_v4();primaryKey;"`
	Username  string    `json:"username" binding:"required" gorm:"uniqueIndex"`
	Email     string    `json:"email" binding:"required,email" gorm:"uniqueIndex"`
	Password  string    `json:"password" binding:"required,min=8"`
	Role      Role      `json:"role" gorm:"type:integer;not null;default:1"`
	Verified  bool      `gorm:"not null"`
	CreatedAt time.Time `json:"created_at" gorm:"not null"`
	UpdatedAt time.Time `json:"updated_at" gorm:"not null"`
}
