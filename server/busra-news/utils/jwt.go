package utils

import (
	"errors"
	"os"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var jwtSecret = []byte(os.Getenv("JWT_SECRET"))


type SignedDetails struct {
	UserID string `json:"userId"`
	Name   string `json:"name"`
	Email  string `json:"email"`
	Role   string `json:"role"`
	jwt.RegisteredClaims
}


func GenerateTokens(userId string, name string, email string, role string) (string, string, error) {
	// ১. .env থেকে মেয়াদ লোড করা
	accessExpiryStr := os.Getenv("ACCESS_TOKEN_EXPIRY_HOUR")
	refreshExpiryStr := os.Getenv("REFRESH_TOKEN_EXPIRY_DAY")

	
	if accessExpiryStr == "" { accessExpiryStr = "15" }
	if refreshExpiryStr == "" { refreshExpiryStr = "22" }

	accessHours, _ := strconv.Atoi(accessExpiryStr)
	refreshDays, _ := strconv.Atoi(refreshExpiryStr)

	
	accessClaims := &SignedDetails{
		UserID: userId,
		Name:   name,
		Email:  email,
		Role:   role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Duration(accessHours) * time.Hour)),
		},
	}
	accessToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims).SignedString(jwtSecret)
	if err != nil {
		return "", "", err
	}


	refreshClaims := &SignedDetails{
		UserID: userId,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Duration(refreshDays) * 24 * time.Hour)),
		},
	}
	refreshToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims).SignedString(jwtSecret)
	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}


func ValidateToken(tokenString string) (*SignedDetails, error) {
	token, err := jwt.ParseWithClaims(tokenString, &SignedDetails{}, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})

	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*SignedDetails)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token")
	}

	return claims, nil
}