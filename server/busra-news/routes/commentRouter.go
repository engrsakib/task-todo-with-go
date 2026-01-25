package routes

import (
	"github.com/engrsakib/news-with-go/controllers"
	"github.com/engrsakib/news-with-go/middleware"
	"github.com/gin-gonic/gin"
)

func CommentRoutes(r *gin.Engine) {
	commentGroup := r.Group("/api/comments")
	
	commentGroup.GET("/post/:id", controllers.GetPostComments)
	commentGroup.Use(middleware.AuthMiddleware()) 
	{
		commentGroup.POST("/create", controllers.CreateComment)
		commentGroup.POST("/create/reply", controllers.CreateComment)
		commentGroup.PUT("/update/:id", controllers.EditComment)
		commentGroup.DELETE("/:id", controllers.DeleteComment)
	}
}