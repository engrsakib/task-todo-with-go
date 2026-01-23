package main

import (
	"os"

	"github.com/engrsakib/news-with-go/config"
	"github.com/engrsakib/news-with-go/routes" // ১. এই লাইনটি খেয়াল করুন (ইমপোর্ট)
	"github.com/gin-gonic/gin"
)

func main() {
	
	config.ConnectDB()

	
	r := gin.Default()


	r.Use(func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	})

	
	r.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "Welcome to Busra News Server!",
		})
	})

	
	routes.AuthRoutes(r)

	
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	r.Run(":" + port)
}