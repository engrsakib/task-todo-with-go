package main

import (
	"os"

	"github.com/engrsakib/news-with-go/config"
	"github.com/gin-gonic/gin"
)

func main() {
	
	config.ConnectDB()


	r := gin.Default()


	r.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "Welcome to Busra News Server running on Go!",
		})
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	
	r.Run(":" + port)
}