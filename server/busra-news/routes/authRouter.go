package routes

import (
	"github.com/engrsakib/news-with-go/controllers"
	"github.com/gin-gonic/gin"
	"github.com/engrsakib/news-with-go/middleware"
)

func AuthRoutes(r *gin.Engine) {
	
	authGroup := r.Group("/api/auth")
	{
		authGroup.POST("/register", controllers.RegisterUser)
		authGroup.POST("/resend-otp", controllers.ResendOTP)
		authGroup.POST("/login", controllers.LoginUser)
		authGroup.POST("/verify", controllers.VerifyOTP)
		authGroup.POST("/forgot-password", controllers.ForgotPassword)
		authGroup.POST("/reset-password", controllers.ResetPassword)
		authGroup.GET("/me", middleware.AuthMiddleware(), controllers.GetProfile)
		authGroup.POST("/change-password", middleware.AuthMiddleware(), controllers.ChangePassword)
		authGroup.PATCH("/update-profile", middleware.AuthMiddleware(), controllers.UpdateUser)
		authGroup.PATCH("/admin/update-user", middleware.AuthMiddleware(), middleware.RoleMiddleware("admin"), controllers.AdminUpdateUser)
	}
}