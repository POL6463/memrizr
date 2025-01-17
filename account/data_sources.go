package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"cloud.google.com/go/storage"
	"github.com/go-redis/redis/v8"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
)

type dataSources struct {
	DB *sqlx.DB
	RedisClient *redis.Client
	StorageClient *storage.Client
}

func initDS() (*dataSources, error) {
	log.Printf("Initializing data sources\n")

	pgHost := os.Getenv("PG_HOST")
	pgPort := os.Getenv("PG_PORT")
	pgUser := os.Getenv("PG_USER")
	pgPassword := os.Getenv("PG_PASSWORD")
	pgDB := os.Getenv("PG_DB")
	pgSSL := os.Getenv("PG_SSL")

	pgConnString := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s", pgHost, pgPort, pgUser, pgPassword, pgDB, pgSSL)
	
	log.Printf("Connecting to Postgresql\n")
	db, err := sqlx.Open("postgres", pgConnString)

	if err != nil {
		return nil, fmt.Errorf("error opening db: %w", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("error connecting to db: %w", err)
	}

	redisHost := os.Getenv("REDIS_HOST")
	redisPort := os.Getenv("REDIS_PORT")

	log.Printf("Connecting to Redis\n")
	rdb := redis.NewClient(&redis.Options{
		Addr:		fmt.Sprintf("%s:%s", redisHost, redisPort),
		Password: 	"",
		DB: 		0,
	})

	_, err = rdb.Ping(context.Background()).Result()

	log.Printf("Connecting to Cloud Storage\n")
	ctx := context.Background()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	storage, err := storage.NewClient(ctx)

	if err != nil {
		return nil, fmt.Errorf("error connection to redis: %w", err)
	}

	return &dataSources{
		DB: 			db,
		RedisClient: 	rdb,
		StorageClient:  storage,
	}, nil
}

func (d *dataSources) close() error {
	if err := d.DB.Close(); err != nil {
		return fmt.Errorf("error closing Postgresql: %w", err)
	}
	
	if err := d.RedisClient.Close(); err != nil {
		return fmt.Errorf("error closing Redis Client: %w", err)
	}

	if err := d.StorageClient.Close(); err != nil {
		return fmt.Errorf("error closing Cloud Storage Client: %w", err)
	}

	return nil
}