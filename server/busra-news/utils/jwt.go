package utils

import (
	"errors"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// টোকেনের সিক্রেট কি (Environment Variable থেকে নিবে)
var jwtSecret = []byte(os.Getenv("JWT_SECRET"))

// CustomClaims - টোকেনের ভেতর আমরা কি কি তথ্য রাখব
type Claims struct {
	UserID string `json:"userId"`
	Role   string `json:"role"`
	jwt.RegisteredClaims
}

// GenerateToken - লগইন করার পর ইউজারকে এই টোকেন দেওয়া হবে
func GenerateToken(userId string, role string) (string, error) {
	// যদি .env লোড না হয়ে থাকে, তবে ক্র্যাশ এড়াতে চেক
	if len(jwtSecret) == 0 {
		jwtSecret = []byte("DEFAULT_SECRET_IF_ENV_MISSING") 
	}

	// টোকেনের মেয়াদ ১ দিন (24 Hours)
	expirationTime := time.Now().Add(24 * time.Hour)

	claims := &Claims{
		UserID: userId,
		Role:   role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}

	// টোকেন তৈরি করা
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

// ValidateToken - টোকেন ঠিক আছে কিনা চেক করা
func ValidateToken(tokenString string) (*Claims, error) {
	claims := &Claims{}

	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, errors.New("invalid token")
	}

	return claims, nil
}