package db

import (
	"fmt"
	"time" // Import time for connection settings

	config "github.com/Mpinyaz/GinWebApp/config"
	"github.com/Mpinyaz/GinWebApp/internal/auth"
	models "github.com/Mpinyaz/GinWebApp/internal/models/users"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func ConnectPGDB(cfg *config.AppCfg) (*gorm.DB, error) {
	var dbinfo string
	if cfg.DBUrl != "" {
		dbinfo = cfg.DBUrl
	} else {
		// Construct DSN from individual fields
		dbinfo = fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%d sslmode=%s",
			cfg.Database.Host,
			cfg.Database.User,
			cfg.Database.Password,
			cfg.Database.DBName,
			cfg.Database.DBPort,
			cfg.Database.SSLMode,
		)
	}

	db, err := gorm.Open(postgres.Open(dbinfo), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database using DSN '%s': %w", dbinfo, err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("failed to get underlying SQL DB instance: %w", err)
	}

	sqlDB.SetMaxIdleConns(10)
	sqlDB.SetMaxOpenConns(100)
	sqlDB.SetConnMaxLifetime(5 * time.Minute)
	if err := db.Exec(`CREATE EXTENSION IF NOT EXISTS "uuid-ossp"`).Error; err != nil {
		return nil, fmt.Errorf("failed to create uuid-ossp extension: %w", err)
	}

	if err = db.AutoMigrate(&models.User{}, &auth.RefreshToken{}, &auth.BlacklistedToken{}); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("failed to automigrate schema: %w", err)
	}

	fmt.Println("Database migration completed successfully!")

	return db, nil
}
