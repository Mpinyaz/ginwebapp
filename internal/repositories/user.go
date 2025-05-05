package repositories

import (
	models "github.com/Mpinyaz/GinWebApp/internal/models/users"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type userGormRepo struct {
	db *gorm.DB
}

func NewUserRepository(db *gorm.DB) UserRepository {
	return &userGormRepo{db}
}

type UserRepository interface {
	Create(user *models.User) error
	FindByID(id uuid.UUID) (*models.User, error)
	FindByEmail(email string) (*models.User, error)
}

func (r *userGormRepo) Create(user *models.User) error {
	return r.db.Create(user).Error
}

func (r *userGormRepo) FindByID(id uuid.UUID) (*models.User, error) {
	var user models.User
	err := r.db.First(&user, "id = ?", id).Error
	return &user, err
}

func (r *userGormRepo) FindByEmail(email string) (*models.User, error) {
	var user models.User
	err := r.db.First(&user, "email = ?", email).Error
	return &user, err
}
