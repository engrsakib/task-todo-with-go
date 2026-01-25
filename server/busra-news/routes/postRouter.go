package routes

import (
	"github.com/engrsakib/news-with-go/controllers"
	"github.com/engrsakib/news-with-go/middleware"
	"github.com/gin-gonic/gin"
)

func PostRoutes(r *gin.Engine) {
	
	postGroup := r.Group("/api/posts")

	
	{
		postGroup.POST("/create", middleware.AuthMiddleware(), controllers.CreatePost)
		postGroup.PATCH("/update/:id", middleware.AuthMiddleware(), controllers.EditPost)
		postGroup.GET("/", controllers.GetAllPosts)
	}
}