package store

import (
	"fmt"
	"log"
	"time"

	"github.com/Mpinyaz/GinWebApp/config"
	"github.com/Mpinyaz/GinWebApp/internal/repositories"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var DB *gorm.DB

type Store struct {
	DB             *gorm.DB
	UserRepository repositories.UserRepository
}

func ConnectDB() {
	var err error
	config, err := config.LoadConfig(".")
	db, err := gorm.Open(postgres.Open(config.DBUrl), &gorm.Config{})

	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	sqlDB, _ := db.DB()
	sqlDB.SetConnMaxIdleTime(10)
	sqlDB.SetConnMaxLifetime(time.Hour)

	DB = db

	fmt.Println("Database connection established")

	RepoStore := &Store{
		DB:             db,
		UserRepository: repositories.NewUserRepository(db),
	}
}
