package config

import (
	"time"

	"github.com/spf13/viper"
	"gorm.io/gorm"
)

var DB *gorm.DB

type AppCfg struct {
	Port           int    `mapstructure:"PORT"`
	DBUrl          string `mapstructure:"DB_URL"`
	REDIS_DB       int    `mapstructure:"REDIS_DB"`
	REDIS_ADDR     string `mapstructure:"REDIS_ADDR"`
	REDIS_PORT     string `mapstructure:"REDIS_PORT"`
	REDIS_PASSWORD string `mapstructure:"REDIS_PASSWORD"`
	Database       struct {
		Host     string `mapstructure:"PSQL_HOST"`
		DBPort   int    `mapstructure:"PSQL_PORT"`
		User     string `mapstructure:"PSQL_USER"`
		Password string `mapstructure:"PSQL_PASSWORD"`
		DBName   string `mapstructure:"PSQL_DBNAME"`
		SSLMode  string `mapstructure:"PSQL_SSLMODE"`
	}
	AccessTokenPrivateKey  string        `mapstructure:"ACCESS_TOKEN_PRIVATE_KEY"`
	AccessTokenPublicKey   string        `mapstructure:"ACCESS_TOKEN_PUBLIC_KEY"`
	SessionTokenPublicKey  string        `mapstructure:"SESSION_TOKEN_PUBLIC_KEY"`
	SessionTokenPrivateKey string        `mapstructure:"SESSION_TOKEN_PRIVATE_KEY"`
	RefreshTokenPrivateKey string        `mapstructure:"REFRESH_TOKEN_PRIVATE_KEY"`
	RefreshTokenPublicKey  string        `mapstructure:"REFRESH_TOKEN_PUBLIC_KEY"`
	AccessTokenExpiresIn   time.Duration `mapstructure:"ACCESS_TOKEN_EXPIRED_IN"`
	RefreshTokenExpiresIn  time.Duration `mapstructure:"REFRESH_TOKEN_EXPIRED_IN"`
	AccessTokenMaxAge      int           `mapstructure:"ACCESS_TOKEN_MAXAGE"`
	RefreshTokenMaxAge     int           `mapstructure:"REFRESH_TOKEN_MAXAGE"`
	SessionTokenMaxAge     int           `mapstructure:"SESSION_TOKEN_MAXAGE"`
}

func LoadConfig(path string) (config *AppCfg, err error) {
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
