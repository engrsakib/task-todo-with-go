package controllers

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/engrsakib/news-with-go/config"
	"github.com/engrsakib/news-with-go/models"
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
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