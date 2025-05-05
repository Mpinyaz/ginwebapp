package main

import (
	"fmt"

	config "github.com/Mpinyaz/GinWebApp/internal"
	models "github.com/Mpinyaz/GinWebApp/models/users"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"log"
	// "os"
)

func main() {
	config, err := config.LoadConfig(".")
	if err != nil {
		log.Fatalf("Error loading config: %v", err)
	}

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
		log.Fatalf("Failed to connect to database: %v", err)
	}

	err = db.AutoMigrate(&models.User{})
	if err != nil {
		log.Fatalf("Failed to automigrate schema: %v", err)
	}

	fmt.Println("Database migration completed successfully!")
	// Get the underlying SQL DB connection
	sqlDB, err := db.DB()
	if err != nil {
		log.Fatalf("Failed to get DB instance: %v", err)
	}

	// Close the database connection
	err = sqlDB.Close()
	if err != nil {
		log.Fatalf("Failed to close database connection: %v", err)
	}

	fmt.Println("Database connection closed properly.")
}
