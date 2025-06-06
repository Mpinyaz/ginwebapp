package cache

import (
	"context"
	"fmt"

	"github.com/Mpinyaz/GinWebApp/config"
	"github.com/go-redis/redis/v8"
)

func ConnectRedis(cfg *config.AppCfg) (*redis.Client, error) {
	redisClient := redis.NewClient(&redis.Options{
		Addr:     "localhost:5488",
		Password: cfg.REDIS_PASSWORD,
		DB:       cfg.REDIS_DB,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_, err := redisClient.Ping(ctx).Result()
	if err != nil {
		return nil, fmt.Errorf("could not connect to Redis: %w", err)
	}

	fmt.Println("Successfully connected to Redis!")
	return redisClient, nil
}

// Optional: Add a helper function to close the connection
func CloseRedis(client *redis.Client) error {
	return client.Close()
}
