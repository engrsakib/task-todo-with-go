package models

import (
	"time"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type Post struct {
	ID          primitive.ObjectID   `bson:"_id,omitempty" json:"id"`
	Title       string               `bson:"title" json:"title" binding:"required"`
	Slug        string               `bson:"slug" json:"slug"`
	Description string               `bson:"description" json:"description" binding:"required"`
	Tags        []string             `bson:"tags" json:"tags"`
	WriterID    primitive.ObjectID   `bson:"writer_id" json:"writer_id"` 
	ReadCounts  int                  `bson:"read_counts" json:"read_counts"`
	Comments    []primitive.ObjectID `bson:"comments" json:"comments"` 
	Status      string               `bson:"status" json:"status"`     
	
	ScheduleTime *time.Time          `bson:"schedule_time,omitempty" json:"schedule_time"` 
	PublishedAt  *time.Time          `bson:"published_at,omitempty" json:"published_at"`   
	
	IsDeleted   bool                 `bson:"is_deleted" json:"is_deleted"`
	CreatedAt   time.Time            `bson:"created_at" json:"created_at"`
	UpdatedAt   time.Time            `bson:"updated_at" json:"updated_at"`
}