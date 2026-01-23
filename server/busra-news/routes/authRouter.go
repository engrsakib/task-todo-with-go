package routes

import (
	"github.com/engrsakib/news-with-go/controllers"
	"github.com/gin-gonic/gin"
)

func AuthRoutes(r *gin.Engine) {
	// অথেন্টিকেশন গ্রুপ
	authGroup := r.Group("/api/auth")
	{
		authGroup.POST("/register", controllers.RegisterUser)
		// পরে আমরা এখানে লগইন এবং ভেরিফাই রাউট যোগ করব
		// authGroup.POST("/login", controllers.LoginUser)
		// authGroup.POST("/verify", controllers.VerifyOTP)
	}
}