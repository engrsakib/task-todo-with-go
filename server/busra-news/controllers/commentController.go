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
	"go.mongodb.org/mongo-driver/mongo"
)

// CreateComment godoc
// @Summary      create a new comment or reply
// @Description  Add a new comment to a news post or reply under another comment. For replies, the parent_id must be provided.
// @Tags         Comments
// @Security     BearerAuth
// @Accept       json
// @Produce      json
// @Param        comment  body      object  true  "Comment Input (post_id, content, parent_id)"
// @Success      201      {object}  map[string]interface{}
// @Failure      400      {object}  map[string]interface{}
// @Router       /comments/create [post]
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


// EditComment godoc
// @Summary      edit a comment
// @Description  Logged-in users can only modify the content of their own comments.
// @Tags         Comments
// @Security     BearerAuth
// @Accept       json
// @Produce      json
// @Param        id       path      string  true  "Comment ID"
// @Param        content  body      object  true  "Updated Content"
// @Success      200      {object}  map[string]interface{}
// @Failure      403      {object}  map[string]interface{}
// @Router       /comments/update/{id} [put]
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


// DeleteComment godoc
// @Summary      delete a comment (soft delete)
// @Description  Comments are soft deleted. Only the author of the comment or an admin can delete it.
// @Tags         Comments
// @Security     BearerAuth
// @Param        id   path      string  true  "Comment ID"
// @Success      200  {object}  map[string]interface{}
// @Failure      404  {object}  map[string]interface{}
// @Router       /comments/{id} [delete]
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


// GetPostComments godoc
// @Summary      get comments and replies for a post
// @Description  Fetch all comments for a specific post along with their nested replies, structured hierarchically.
// @Tags         Comments
// @Produce      json
// @Param        id   path      string  true  "Post ID"
// @Success      200  {object}  map[string]interface{}
// @Failure      400  {object}  map[string]interface{}
// @Router       /comments/post/{id} [get]
func GetPostComments(c *gin.Context) {
	postID := c.Param("id")
	objID, err := primitive.ObjectIDFromHex(postID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid Post ID"})
		return
	}

	var ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	commentCollection := config.GetCollection("comments")

	
	pipeline := mongo.Pipeline{
		
		bson.D{{Key: "$match", Value: bson.D{
			{Key: "post_id", Value: objID},
			{Key: "is_deleted", Value: false},
		}}},
		
		bson.D{{Key: "$lookup", Value: bson.D{
			{Key: "from", Value: "users"},
			{Key: "localField", Value: "user_id"},
			{Key: "foreignField", Value: "_id"},
			{Key: "as", Value: "user"},
		}}},
		
		bson.D{{Key: "$unwind", Value: "$user"}},
		
		bson.D{{Key: "$project", Value: bson.D{
			{Key: "_id", Value: 1},
			{Key: "content", Value: 1},
			{Key: "parent_id", Value: 1},
			{Key: "created_at", Value: 1},
			{Key: "user", Value: bson.D{
				{Key: "_id", Value: "$user._id"},
				{Key: "name", Value: "$user.name"},
			}},
		}}},
		
		bson.D{{Key: "$sort", Value: bson.D{{Key: "created_at", Value: 1}}}},
	}

	cursor, err := commentCollection.Aggregate(ctx, pipeline)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch comments"})
		return
	}

	
	type CommentResponse struct {
		ID        string              `json:"id" bson:"_id"`
		Content   string              `json:"content" bson:"content"`
		ParentID  *primitive.ObjectID `json:"parent_id" bson:"parent_id"`
		CreatedAt time.Time           `json:"created_at" bson:"created_at"`
		User      struct {
			ID   string `json:"id" bson:"_id"`
			Name string `json:"name" bson:"name"`
		} `json:"user" bson:"user"`
		Replies []*CommentResponse `json:"replies"` 
	}

	var allComments []*CommentResponse
	if err = cursor.All(ctx, &allComments); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error decoding comments"})
		return
	}

	
	commentMap := make(map[string]*CommentResponse)
	var rootComments []*CommentResponse

	
	for _, comment := range allComments {
		comment.Replies = []*CommentResponse{}
		commentMap[comment.ID] = comment
	}

	
	for _, comment := range allComments {
		if comment.ParentID != nil {
			parentIDHex := comment.ParentID.Hex()
			if parent, exists := commentMap[parentIDHex]; exists {
				parent.Replies = append(parent.Replies, comment)
			}
		} else {
			rootComments = append(rootComments, comment)
		}
	}

	c.JSON(http.StatusOK, gin.H{"status": true, "data": rootComments})
}