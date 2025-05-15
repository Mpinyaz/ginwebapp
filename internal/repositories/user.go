package repositories

import (
	models "github.com/Mpinyaz/GinWebApp/internal/models/users"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type UserRepo struct {
	DB *gorm.DB
}

func NewUserRepository(db *gorm.DB) UserRepository {
	return &UserRepo{db}
}

type UserRepository interface {
	Create(user *models.User) error
	FindByID(id uuid.UUID) (*models.User, error)
	FindByEmail(email string) (*models.User, error)
	FindByUserame(username string) (*models.User, error)
}

func (r *UserRepo) Create(user *models.User) error {
	return r.DB.Create(user).Error
}

func (r *UserRepo) FindByID(id uuid.UUID) (*models.User, error) {
	var user models.User
	err := r.DB.First(&user, "id = ?", id).Error
	return &user, err
}

func (r *UserRepo) FindByEmail(email string) (*models.User, error) {
	var user models.User
	err := r.DB.First(&user, "email = LOWER(?)", email).Error
	return &user, err
}

func (r *UserRepo) FindByUserame(username string) (*models.User, error) {
	var user models.User
	err := r.DB.First(&user, "username = LOWER(?)", username).Error
	return &user, err
}
