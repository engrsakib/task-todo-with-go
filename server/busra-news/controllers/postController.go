package controllers

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
	"math"

	"github.com/engrsakib/news-with-go/config"
	"github.com/engrsakib/news-with-go/models"
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)


func CreatePost(c *gin.Context) {
	
	var input struct {
		Title        string     `json:"title" binding:"required"`
		Slug         string     `json:"slug"` 
		Description  string     `json:"description" binding:"required"`
		Tags         []string   `json:"tags"`
		Status       string     `json:"status"`
		ScheduleTime *time.Time `json:"schedule_time"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	
	var ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	postCollection := config.GetCollection("posts")


	userId, exists := c.Get("userId")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized request"})
		return
	}
	writerObjID, _ := primitive.ObjectIDFromHex(userId.(string))


	baseString := input.Slug
	if baseString == "" {
		baseString = input.Title
	}
	
	finalSlug := getUniqueSlug(ctx, postCollection, baseString)

	
	status := "draft"
	var publishedAt *time.Time
	var scheduleTime *time.Time

	switch input.Status {
	case "publish":
		status = "publish"
		now := time.Now()
		publishedAt = &now
	case "schedule":
		status = "schedule"
		if input.ScheduleTime == nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Schedule time is required"})
			return
		}
		scheduleTime = input.ScheduleTime
	default:
		status = "draft"
	}

	
	newPost := models.Post{
		ID:           primitive.NewObjectID(),
		Title:        input.Title,
		Slug:         finalSlug, 
		Description:  input.Description,
		Tags:         input.Tags,
		WriterID:     writerObjID,
		ReadCounts:   0,
		Comments:     []primitive.ObjectID{},
		Status:       status,
		ScheduleTime: scheduleTime,
		PublishedAt:  publishedAt,
		IsDeleted:    false,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	_, err := postCollection.InsertOne(ctx, newPost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create post"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"status":  true,
		"message": "Post created successfully",
		"data":    newPost,
	})
}


func EditPost(c *gin.Context) {
	
	postID := c.Param("id")
	objID, err := primitive.ObjectIDFromHex(postID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid Post ID"})
		return
	}

	
	var input struct {
		Title        string     `json:"title"`
		Slug         string     `json:"slug"`
		Description  string     `json:"description"`
		Tags         []string   `json:"tags"`
		Status       string     `json:"status"`
		ScheduleTime *time.Time `json:"schedule_time"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	
	var ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	postCollection := config.GetCollection("posts")

	var existingPost models.Post
	err = postCollection.FindOne(ctx, bson.M{"_id": objID}).Decode(&existingPost)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Post not found"})
		return
	}

	userID, _ := c.Get("userId")
	userRole, _ := c.Get("role")

	
	if userRole != "ADMIN" && existingPost.WriterID.Hex() != userID.(string) {
		c.JSON(http.StatusForbidden, gin.H{"error": "You are not allowed to edit this post"})
		return
	}

	updateFields := bson.M{"updated_at": time.Now()}

	if input.Title != "" {
		updateFields["title"] = input.Title
	}
	if input.Description != "" {
		updateFields["description"] = input.Description
	}
	if input.Tags != nil {
		updateFields["tags"] = input.Tags
	}

	
	if input.Slug != "" && input.Slug != existingPost.Slug {
		
		updateFields["slug"] = getUniqueSlug(ctx, postCollection, input.Slug)
	}


	if input.Status != "" {
		updateFields["status"] = input.Status

		switch input.Status {
		case "publish":
			now := time.Now()
			updateFields["published_at"] = now

		case "schedule":
			if input.ScheduleTime != nil {
				updateFields["schedule_time"] = input.ScheduleTime
			} else if existingPost.ScheduleTime == nil {
				
				c.JSON(http.StatusBadRequest, gin.H{"error": "Schedule time is required"})
				return
			}
		}
	}

	
	_, err = postCollection.UpdateOne(ctx, bson.M{"_id": objID}, bson.M{"$set": updateFields})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update post"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":  true,
		"message": "Post updated successfully",
		"updated_fields": updateFields,
	})
}

func getUniqueSlug(ctx context.Context, collection *mongo.Collection, text string) string {
	
	
	reg, _ := regexp.Compile("[^a-z0-9]+")
	slug := strings.ToLower(text)
	slug = reg.ReplaceAllString(slug, "-")
	slug = strings.Trim(slug, "-") 

	
	originalSlug := slug
	counter := 1

	for {
		
		count, err := collection.CountDocuments(ctx, bson.M{"slug": slug})
		
		
		if err == nil && count == 0 {
			break
		}

		slug = fmt.Sprintf("%s-%d", originalSlug, counter)
		counter++
	}

	return slug
}



func GetAllPosts(c *gin.Context) {
	
	pageStr := c.DefaultQuery("page", "1")
	limitStr := c.DefaultQuery("limit", "10")

	page, _ := strconv.Atoi(pageStr)
	limit, _ := strconv.Atoi(limitStr)
	skip := (page - 1) * limit

	var ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	postCollection := config.GetCollection("posts")

	
	filter := bson.M{"is_deleted": false}

	
	projection := bson.M{
		"_id":          1,
		"title":        1,
		"slug":         1,
		"status":       1,
		"read_counts":  1,
		"writer_id":    1, 
		"tags":         1,
		"published_at": 1,
		"created_at":   1,
		// "description": 0, 
		// "comments": 0,    
	}

	
	findOptions := options.Find()
	findOptions.SetProjection(projection)
	findOptions.SetLimit(int64(limit))
	findOptions.SetSkip(int64(skip))
	findOptions.SetSort(bson.M{"created_at": -1}) 

	
	var posts []bson.M 
	cursor, err := postCollection.Find(ctx, filter, findOptions)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error fetching posts"})
		return
	}
	defer cursor.Close(ctx)

	if err = cursor.All(ctx, &posts); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error decoding posts"})
		return
	}

	total, _ := postCollection.CountDocuments(ctx, filter)

	c.JSON(http.StatusOK, gin.H{
		"status": true,
		"data":   posts,
		"pagination": gin.H{
			"current_page": page,
			"limit":        limit,
			"total_posts":  total,
			"total_pages":  int(math.Ceil(float64(total) / float64(limit))),
		},
	})
}



func GetPostBySlug(c *gin.Context) {
	
	slug := c.Param("slug")

	var ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	postCollection := config.GetCollection("posts")

	
	filter := bson.M{"slug": slug, "is_deleted": false}
	
	
	update := bson.M{"$inc": bson.M{"read_counts": 1}}
	
	
	opts := options.FindOneAndUpdate().SetReturnDocument(options.After)

	var post models.Post
	err := postCollection.FindOneAndUpdate(ctx, filter, update, opts).Decode(&post)

	if err != nil {
		
		if err == mongo.ErrNoDocuments {
			c.JSON(http.StatusNotFound, gin.H{"error": "Post not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error fetching post"})
		return
	}

	
	c.JSON(http.StatusOK, gin.H{
		"status": true,
		"data":   post,
	})
}