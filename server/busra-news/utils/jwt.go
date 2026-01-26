package utils

import (
	"errors"
	"os"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
)


type SignedDetails struct {
	UserID string `json:"userId"`
	Name   string `json:"name"`
	Email  string `json:"email"`
	Role   string `json:"role"`
	jwt.RegisteredClaims
}


func GenerateTokens(userId string, name string, email string, role string) (string, string, error) {

	accessSecret := []byte(os.Getenv("JWT_SECRET"))
	refreshSecret := []byte(os.Getenv("REFRESH_SECRET"))

	
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
	accessToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims).SignedString(accessSecret)
	if err != nil {
		return "", "", err
	}

	
	refreshClaims := &SignedDetails{
		UserID: userId,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Duration(refreshDays) * 24 * time.Hour)),
		},
	}
	refreshToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims).SignedString(refreshSecret)
	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}


func ValidateToken(tokenString string) (*SignedDetails, error) {
	token, err := jwt.ParseWithClaims(tokenString, &SignedDetails{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("JWT_SECRET")), nil // ✅ সরাসরি env থেকে
	})

	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*SignedDetails)
	if !ok || !token.Valid {
		return nil, errors.New("invalid access token")
	}

	return claims, nil
}


func ValidateRefreshToken(tokenString string) (*SignedDetails, error) {
	token, err := jwt.ParseWithClaims(tokenString, &SignedDetails{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("REFRESH_SECRET")), nil 
	})

	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*SignedDetails)
	if !ok || !token.Valid {
		return nil, errors.New("invalid refresh token")
	}

	return claims, nil
}