package store

import (
	"fmt"

	config "github.com/Mpinyaz/GinWebApp/config"
	models "github.com/Mpinyaz/GinWebApp/internal/models/users"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// SetupDatabase connects to the database, performs automigration, and returns the DB connection.

func initDB(config config.AppConfig) (*gorm.DB, error) {

	dsn := config.DBUrl
	if dsn == "" {
		// Construct DSN from individual fields if DBUrl is not provided
		dsn = fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%d sslmode=%s",
			config.Database.Host,
			config.Database.User,
			config.Database.Password,
			config.Database.DBName,
			config.Database.DBPort,
			config.Database.SSLMode,
		)
	}

	// Connect to the database
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// AutoMigrate the schema
	err = db.AutoMigrate(&models.User{})
	if err != nil {
		return nil, fmt.Errorf("failed to automigrate schema: %w", err)
	}

	fmt.Println("Database migration completed successfully!")
	return db, nil
}
