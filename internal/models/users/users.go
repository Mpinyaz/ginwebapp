package models

import (
	"github.com/google/uuid"
	"time"
)

type Role string

const (
	RoleAdmin Role = "admin"
	RoleUser  Role = "user"
	RoleGuest Role = "guest"
)

type User struct {
	ID        uuid.UUID `json:"id" gorm:"type:uuid;default:uuid_generate_v4();primaryKey;"`
	Username  string    `json:"username" binding:"required" gorm:"uniqueIndex"`
	Email     string    `json:"email" binding:"required,email" gorm:"uniqueIndex"`
	Password  string    `json:"password" binding:"required,min=8"`
	Role      Role      `json:"role" gorm:"type:varchar(20);" binding:"required"`
	Verified  bool      `gorm:"not null"`
	CreatedAt time.Time `json:"created_at" gorm:"not null"`
	UpdatedAt time.Time `json:"updated_at" gorm:"not null"`
}
