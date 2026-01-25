package routes

import (
	"github.com/engrsakib/news-with-go/controllers"
	"github.com/engrsakib/news-with-go/middleware"
	"github.com/gin-gonic/gin"
)

func AuthRoutes(r *gin.Engine) {
	
	authGroup := r.Group("/api/auth")

	
	{
		authGroup.POST("/register", controllers.RegisterUser)
		authGroup.POST("/login", controllers.LoginAsUser)
		authGroup.POST("/refresh-token", controllers.RefreshToken)
		authGroup.POST("/verify", controllers.VerifyOTP)
		authGroup.POST("/resend-otp", controllers.ResendOTP)
		authGroup.POST("/forgot-password", controllers.ForgotPassword)
		authGroup.POST("/reset-password", controllers.ResetPassword)
	}

	protected := authGroup.Group("/")
	protected.Use(middleware.AuthMiddleware())
	{
		protected.GET("/me", controllers.GetProfile)
		protected.POST("/change-password", controllers.ChangePassword)
		protected.PATCH("/update-profile", controllers.UpdateUser)

	
		admin := protected.Group("/admin")
		admin.Use(middleware.RoleMiddleware("admin"))
		{
			admin.PATCH("/update-user", controllers.AdminUpdateUser)
			admin.GET("/users", controllers.GetAllUsers)
			
			admin.DELETE("/delete-user/:id", controllers.DeleteUser)
		}
	}
}