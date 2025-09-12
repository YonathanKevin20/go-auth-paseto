package config

import (
	"fmt"
	"go-auth-paseto/models"
	"log"
	"os"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var DB *gorm.DB

func ConnectDB() (*gorm.DB, error) {
	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=disable TimeZone=Asia/Shanghai",
		os.Getenv("DB_HOST"),
		os.Getenv("DB_USER"),
		os.Getenv("DB_PASSWORD"),
		os.Getenv("DB_NAME"),
		os.Getenv("DB_PORT"),
	)

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		PrepareStmt: true,
	})
	if err != nil {
		log.Fatal("Failed to connect to database")
	}

	DB = db
	return db, nil
}

func Migrate() error {
	// Run manual migrations
	if err := createUserRoleEnum(); err != nil {
		return err
	}

	// Run AutoMigrate for all models
	err := DB.AutoMigrate(
		&models.User{},
		// Add any other models here
	)
	if err != nil {
		return err
	}

	return nil
}

func createUserRoleEnum() error {
	var exists bool
	err := DB.Raw("SELECT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'user_role')").Scan(&exists).Error
	if err != nil {
		return err
	}

	if !exists {
		if err := DB.Exec("CREATE TYPE user_role AS ENUM ('admin', 'operator')").Error; err != nil {
			return err
		}
	}

	return nil
}
