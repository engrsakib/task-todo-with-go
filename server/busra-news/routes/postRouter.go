package routes

import (
	"github.com/engrsakib/news-with-go/controllers"
	"github.com/engrsakib/news-with-go/middleware"
	"github.com/gin-gonic/gin"
)

func PostRoutes(r *gin.Engine) {
	
	postGroup := r.Group("/api/posts")

	{
		postGroup.GET("/", controllers.GetAllPosts)        
		postGroup.GET("/:slug", controllers.GetPostBySlug) 

	}


	authGroup := postGroup.Group("/")
	authGroup.Use(middleware.AuthMiddleware())
	{
		authGroup.POST("/create", controllers.CreatePost)
		authGroup.PATCH("/status/:id", controllers.ChangePostStatus)
		authGroup.PUT("/update/:id", controllers.EditPost) 
	}
}