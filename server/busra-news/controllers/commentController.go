package controllers

import (
	"context"
	"net/http"
	"time"

	"github.com/engrsakib/news-with-go/config"
	"github.com/engrsakib/news-with-go/models"
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)


func CreateComment(c *gin.Context) {
	
	var input struct {
		PostID   string `json:"post_id" binding:"required"`
		Content  string `json:"content" binding:"required"`
		ParentID string `json:"parent_id"` 
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	
	postObjID, err := primitive.ObjectIDFromHex(input.PostID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid Post ID"})
		return
	}

	userId, _ := c.Get("userId")
	userObjID, _ := primitive.ObjectIDFromHex(userId.(string))

	
	var parentObjID *primitive.ObjectID
	if input.ParentID != "" {
		pID, err := primitive.ObjectIDFromHex(input.ParentID)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid Parent Comment ID"})
			return
		}
		parentObjID = &pID
		
		
	}

	
	newComment := models.Comment{
		ID:        primitive.NewObjectID(),
		PostID:    postObjID,
		UserID:    userObjID,
		Content:   input.Content,
		ParentID:  parentObjID,
		IsDeleted: false,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	var ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	commentCollection := config.GetCollection("comments")
	postCollection := config.GetCollection("posts")

	
	_, err = commentCollection.InsertOne(ctx, newComment)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to post comment"})
		return
	}


	go func() {
		
		postCtx, postCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer postCancel()
		postCollection.UpdateOne(postCtx, bson.M{"_id": postObjID}, bson.M{"$inc": bson.M{"comment_counts": 1}})
	}()

	c.JSON(http.StatusCreated, gin.H{
		"status":  true,
		"message": "Comment added successfully",
		"data":    newComment,
	})
}


func EditComment(c *gin.Context) {
	
	commentID := c.Param("id")
	objID, err := primitive.ObjectIDFromHex(commentID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid Comment ID"})
		return
	}

	
	var input struct {
		Content string `json:"content" binding:"required"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	commentCollection := config.GetCollection("comments")

	
	var existingComment models.Comment
	err = commentCollection.FindOne(ctx, bson.M{"_id": objID, "is_deleted": false}).Decode(&existingComment)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Comment not found"})
		return
	}

	
	userID, _ := c.Get("userId")
	if existingComment.UserID.Hex() != userID.(string) {
		c.JSON(http.StatusForbidden, gin.H{"error": "You can only edit your own comment"})
		return
	}

	// ৫. আপডেট করা
	update := bson.M{
		"$set": bson.M{
			"content":    input.Content,
			"updated_at": time.Now(),
		},
	}
	_, err = commentCollection.UpdateOne(ctx, bson.M{"_id": objID}, update)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update comment"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":  true,
		"message": "Comment updated successfully",
	})
}


func DeleteComment(c *gin.Context) {
	commentID := c.Param("id")
	objID, err := primitive.ObjectIDFromHex(commentID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid Comment ID"})
		return
	}

	var ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	commentCollection := config.GetCollection("comments")
	postCollection := config.GetCollection("posts")

	
	var existingComment models.Comment
	err = commentCollection.FindOne(ctx, bson.M{"_id": objID}).Decode(&existingComment)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Comment not found"})
		return
	}

	
	if existingComment.IsDeleted {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Comment already deleted"})
		return
	}

	
	userID, _ := c.Get("userId")
	userRole, _ := c.Get("role")

	if userRole != "ADMIN" && existingComment.UserID.Hex() != userID.(string) {
		c.JSON(http.StatusForbidden, gin.H{"error": "You are not allowed to delete this comment"})
		return
	}


	update := bson.M{
		"$set": bson.M{
			"is_deleted": true,
			"updated_at": time.Now(),
		},
	}
	_, err = commentCollection.UpdateOne(ctx, bson.M{"_id": objID}, update)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete comment"})
		return
	}

	
	go func() {
		postCtx, postCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer postCancel()
		
		postCollection.UpdateOne(postCtx, bson.M{"_id": existingComment.PostID}, bson.M{"$inc": bson.M{"comment_counts": -1}})
	}()

	c.JSON(http.StatusOK, gin.H{
		"status":  true,
		"message": "Comment deleted successfully",
	})
}