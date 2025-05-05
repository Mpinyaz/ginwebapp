package config

import (
	"github.com/spf13/viper"
	"gorm.io/gorm"
	"time"
)

var DB *gorm.DB

type appConfig struct {
	Port     int    `mapstructure:"PORT"`
	DBUrl    string `mapstructure:"DB_URL"`
	Database struct {
		Host     string `mapstructure:"PSQL_HOST"`
		DBPort   int    `mapstructure:"PSQL_PORT"`
		User     string `mapstructure:"PSQL_USER"`
		Password string `mapstructure:"PSQL_PASSWORD"`
		DBName   string `mapstructure:"PSQL_DBNAME"`
		SSLMode  string `mapstructure:"PSQL_SSLMODE"`
	}
	AccessTokenPrivateKey  string        `mapstructure:"ACCESS_TOKEN_PRIVATE_KEY"`
	AccessTokenPublicKey   string        `mapstructure:"ACCESS_TOKEN_PUBLIC_KEY"`
	RefreshTokenPrivateKey string        `mapstructure:"REFRESH_TOKEN_PRIVATE_KEY"`
	RefreshTokenPublicKey  string        `mapstructure:"REFRESH_TOKEN_PUBLIC_KEY"`
	AccessTokenExpiresIn   time.Duration `mapstructure:"ACCESS_TOKEN_EXPIRED_IN"`
	RefreshTokenExpiresIn  time.Duration `mapstructure:"REFRESH_TOKEN_EXPIRED_IN"`
	AccessTokenMaxAge      int           `mapstructure:"ACCESS_TOKEN_MAXAGE"`
	RefreshTokenMaxAge     int           `mapstructure:"REFRESH_TOKEN_MAXAGE"`
}

func LoadConfig(path string) (config *appConfig, err error) {
	viper.AddConfigPath(path)
	viper.SetConfigType("env")
	viper.SetConfigName(".env")

	viper.AutomaticEnv()

	err = viper.ReadInConfig()
	if err != nil {
		return
	}

	err = viper.Unmarshal(&config)
	return
}
