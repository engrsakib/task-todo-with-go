package models

import (
	"time"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type Comment struct {
	ID        primitive.ObjectID  `bson:"_id,omitempty" json:"id"`
	PostID    primitive.ObjectID  `bson:"post_id" json:"post_id"`         
	UserID    primitive.ObjectID  `bson:"user_id" json:"user_id"`        
	Content   string              `bson:"content" json:"content" binding:"required"`
	
	
	ParentID  *primitive.ObjectID `bson:"parent_id,omitempty" json:"parent_id"` 

	IsDeleted bool                `bson:"is_deleted" json:"is_deleted"`
	CreatedAt time.Time           `bson:"created_at" json:"created_at"`
	UpdatedAt time.Time           `bson:"updated_at" json:"updated_at"`
}