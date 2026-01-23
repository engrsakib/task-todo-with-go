package config

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)


var DB *mongo.Database


func ConnectDB() {
	
	err := godotenv.Load()
	if err != nil {
		log.Println("⚠️  Note: .env file not found (checking system env vars)")
	}

	mongoURI := os.Getenv("MONGO_URI")
	dbName := os.Getenv("DB_NAME")

	if mongoURI == "" {
		log.Fatal("❌ MONGO_URI is missing in .env file!")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()


	clientOptions := options.Client().ApplyURI(mongoURI)

	
	client, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		log.Fatal("❌ Connection Failed:", err)
	}


	err = client.Ping(ctx, nil)
	if err != nil {
		log.Fatal("❌ Ping Failed:", err)
	}

	fmt.Println("✅ Successfully Connected to MongoDB Atlas!")
	
	
	DB = client.Database(dbName)
}

func GetCollection(collectionName string) *mongo.Collection {
	if DB == nil {
		log.Fatal("❌ Database connection is not initialized!")
	}
	return DB.Collection(collectionName)
}