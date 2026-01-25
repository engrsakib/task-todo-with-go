package controllers

import (
	"context"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/engrsakib/news-with-go/config"
	"github.com/engrsakib/news-with-go/models"
	"github.com/engrsakib/news-with-go/utils"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/gomail.v2"
)


func RegisterUser(c *gin.Context) {
	var user models.User
	var ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	userCollection := config.GetCollection("users")

	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	
	count, err := userCollection.CountDocuments(ctx, bson.M{"email": user.Email})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error checking user"})
		return
	}
	if count > 0 {
		c.JSON(http.StatusConflict, gin.H{"error": "Email already exists!"})
		return
	}

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(user.Password), 14)
	user.Password = string(hashedPassword)

	
	user.ID = primitive.NewObjectID()
	user.CreatedAt = time.Now()
	user.UpdatedAt = time.Now()
	user.Verified = false
	user.Is_Deleted = false
	user.Role = "USER" 

	otp := generateOTP()
	user.OTP = otp


	_, err = userCollection.InsertOne(ctx, user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
		return
	}


	emailErr := sendOTPEmail(user.Email, otp)
	if emailErr != nil {
		
		c.JSON(http.StatusCreated, gin.H{
			"message": "User created but failed to send OTP email.",
			"userId":  user.ID,
			"error":   emailErr.Error(),
		})
		return
	}

	
	c.JSON(http.StatusCreated, gin.H{
		"message": "User registered successfully! Please check your email for OTP.",
		"userId":  user.ID,
	})
}


func generateOTP() string {
	rand.Seed(time.Now().UnixNano())
	min := 1000
	max := 9999
	return strconv.Itoa(rand.Intn(max-min+1) + min)
}


func sendOTPEmail(toEmail string, otp string) error {
	// .env থেকে ইমেইল ক্রেডেনশিয়াল নেওয়া
	smtpHost := os.Getenv("SMTP_HOST")
	smtpPort, _ := strconv.Atoi(os.Getenv("SMTP_PORT"))
	smtpEmail := os.Getenv("SMTP_EMAIL")
	smtpPassword := os.Getenv("SMTP_PASSWORD")

	m := gomail.NewMessage()
	m.SetHeader("From", smtpEmail)
	m.SetHeader("To", toEmail)
	m.SetHeader("Subject", "Your Verification Code - Busra News")
	
	// ইমেইল বডি (HTML)
	body := fmt.Sprintf(`
		<h1>Welcome to Busra News!</h1>
		<p>Your verification code is:</p>
		<h2 style="color: blue;">%s</h2>
		<p>Please enter this code to verify your account.</p>
	`, otp)
	
	m.SetBody("text/html", body)

	// ইমেইল পাঠানো
	d := gomail.NewDialer(smtpHost, smtpPort, smtpEmail, smtpPassword)

	if err := d.DialAndSend(m); err != nil {
		log.Println("Failed to send email:", err)
		return err
	}
	
	return nil
}


func ResendOTP(c *gin.Context) {
	var input struct {
		Email string `json:"email" binding:"required,email"`
	}

	var ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	userCollection := config.GetCollection("users")


	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var user models.User
	err := userCollection.FindOne(ctx, bson.M{"email": input.Email}).Decode(&user)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found with this email"})
		return
	}

	
	if user.Verified {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Account is already verified. Please login."})
		return
	}

	newOTP := generateOTP()

	update := bson.M{"$set": bson.M{"otp": newOTP, "updated_at": time.Now()}}
	_, err = userCollection.UpdateOne(ctx, bson.M{"email": input.Email}, update)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update OTP"})
		return
	}

	
	emailErr := sendOTPEmail(user.Email, newOTP)
	if emailErr != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send email. Please try again later."})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "A new verification code has been sent to your email."})
}

func LoginAsUser(c *gin.Context) {
	var input struct {
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required"`
	}

	
	var ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	userCollection := config.GetCollection("users")

	
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	
	var user models.User
	err := userCollection.FindOne(ctx, bson.M{"email": input.Email}).Decode(&user)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid email or password"})
		return
	}

	
	if user.Is_Deleted {
		c.JSON(http.StatusForbidden, gin.H{"error": "Your account has been deactivated. Please contact support."})
		return
	}

	if !user.Verified {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Please verify your email first!"})
		return
	}

	
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(input.Password))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid email or password"})
		return
	}
	
	
	accessToken, err := utils.GenerateToken(user.ID.Hex(), user.Role, os.Getenv("JWT_SECRET"), time.Hour*1)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate access token"})
		return
	}

	refreshToken, err := utils.GenerateToken(user.ID.Hex(), user.Role, os.Getenv("REFRESH_SECRET"), time.Hour*24*7)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate refresh token"})
		return
	}


	response := struct {
    Status       bool                   `json:"status"`
    Message      string                 `json:"message"`
    User         map[string]interface{} `json:"user"`
    AccessToken  string                 `json:"access_token"`
    RefreshToken string                 `json:"refresh_token"`
}{
    
    Status:  true,
    Message: "Login successful!",
    User: gin.H{
        "id":    user.ID,
        "name":  user.Name,
        "email": user.Email,
        "role":  user.Role,
    },
    AccessToken:  accessToken,
    RefreshToken: refreshToken,
}

c.JSON(http.StatusOK, response)
	
}


func VerifyOTP(c *gin.Context) {
	var input struct {
		Email string `json:"email" binding:"required,email"`
		OTP   string `json:"otp" binding:"required"`
	}

	var ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	userCollection := config.GetCollection("users")

	// ১. ইনপুট চেক
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// ২. ডাটাবেসে ইউজার খোঁজা
	var user models.User
	err := userCollection.FindOne(ctx, bson.M{"email": input.Email}).Decode(&user)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	
	if user.Verified {
		c.JSON(http.StatusOK, gin.H{"message": "Account is already verified"})
		return
	}

	
	if user.OTP != input.OTP {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid OTP provided"})
		return
	}

	
	update := bson.M{
		"$set": bson.M{"verified": true, "otp": ""},
	}
	_, err = userCollection.UpdateOne(ctx, bson.M{"email": input.Email}, update)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to verify user"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Account verified successfully! You can login now."})
}


func ForgotPassword(c *gin.Context) {
	var input struct {
		Email string `json:"email" binding:"required,email"`
	}

	var ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	userCollection := config.GetCollection("users")

	// ১. ইনপুট চেক
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// ২. ইউজার আছে কিনা দেখা
	var user models.User
	err := userCollection.FindOne(ctx, bson.M{"email": input.Email}).Decode(&user)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found with this email"})
		return
	}

	// ৩. নতুন OTP তৈরি এবং সেভ করা
	otp := generateOTP()
	update := bson.M{"$set": bson.M{"otp": otp, "updated_at": time.Now()}}
	
	_, err = userCollection.UpdateOne(ctx, bson.M{"email": input.Email}, update)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate OTP"})
		return
	}

	// ৪. ইমেইল পাঠানো
	sendErr := sendOTPEmail(user.Email, otp)
	if sendErr != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send email"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Password reset OTP sent to your email."})
}

func ResetPassword(c *gin.Context) {
	var input struct {
		Email       string `json:"email" binding:"required,email"`
		OTP         string `json:"otp" binding:"required"`
		NewPassword string `json:"newPassword" binding:"required,min=6"`
	}

	var ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	userCollection := config.GetCollection("users")

	
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	
	var user models.User
	err := userCollection.FindOne(ctx, bson.M{"email": input.Email}).Decode(&user)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}


	if user.OTP != input.OTP {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid OTP"})
		return
	}


	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(input.NewPassword), 14)


	update := bson.M{
		"$set": bson.M{
			"password":   string(hashedPassword),
			"otp":        "", 
			"updated_at": time.Now(),
		},
	}

	_, err = userCollection.UpdateOne(ctx, bson.M{"email": input.Email}, update)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to reset password"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Password reset successfully! You can login now."})
}


func GetProfile(c *gin.Context) {
	
	userId, exists := c.Get("userId")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized request"})
		return
	}

	var ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	userCollection := config.GetCollection("users")

	
	objID, err := primitive.ObjectIDFromHex(userId.(string))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}


	var user models.User
	err = userCollection.FindOne(ctx, bson.M{"_id": objID}).Decode(&user)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	
	c.JSON(http.StatusOK, gin.H{
		"status": true,
		"data": gin.H{
			"id":    user.ID,
			"name":  user.Name,
			"email": user.Email,
			"role":  user.Role,
			"verified": user.Verified,
			"joined_at": user.CreatedAt,
		},
	})
}



func ChangePassword(c *gin.Context) {
	
	var input struct {
		CurrentPassword string `json:"currentPassword" binding:"required"`
		NewPassword     string `json:"newPassword" binding:"required,min=6"`
		RetypePassword  string `json:"retypePassword" binding:"required,eqfield=NewPassword"` // eqfield চেক করে নিউ 
	}

	
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	
	userId, _ := c.Get("userId")
	
	var ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	userCollection := config.GetCollection("users")

	
	objID, _ := primitive.ObjectIDFromHex(userId.(string))
	var user models.User
	err := userCollection.FindOne(ctx, bson.M{"_id": objID}).Decode(&user)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(input.CurrentPassword))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Current password is incorrect"})
		return
	}


	hashedNewPassword, _ := bcrypt.GenerateFromPassword([]byte(input.NewPassword), 14)

	
	update := bson.M{
		"$set": bson.M{
			"password":   string(hashedNewPassword),
			"updated_at": time.Now(),
		},
	}
	_, err = userCollection.UpdateOne(ctx, bson.M{"_id": objID}, update)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update password"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":  true,
		"message": "Password changed successfully!",
	})
}




func UpdateUser(c *gin.Context) {
	
	var input struct {
		TargetUserID string `json:"targetUserId"` 
		Name         string `json:"name" binding:"required"`
	}

	
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	
	requesterID, _ := c.Get("userId")
	requesterRole, _ := c.Get("role")

	
	updateID := requesterID.(string) 

	
	if input.TargetUserID != "" {
		
		if requesterRole == "ADMIN" {
			updateID = input.TargetUserID 
		} else {
		
			c.JSON(http.StatusForbidden, gin.H{"error": "Only Admins can update other users"})
			return
		}
	}

	var ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	userCollection := config.GetCollection("users")

	
	objID, err := primitive.ObjectIDFromHex(updateID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID format"})
		return
	}

	
	update := bson.M{
		"$set": bson.M{
			"name":       input.Name,
			"updated_at": time.Now(),
		},
	}

	result, err := userCollection.UpdateOne(ctx, bson.M{"_id": objID}, update)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update profile"})
		return
	}

	if result.MatchedCount == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":  true,
		"message": "Profile updated successfully!",
		"data": gin.H{
			"updatedId": updateID,
			"name":      input.Name,
		},
	})
}

func AdminUpdateUser(c *gin.Context) {
	
	var input struct {
		TargetUserID string `json:"targetUserId" binding:"required"` 
		Role         string `json:"role"`         
		Verified     *bool  `json:"verified"`     
		NewPassword  string `json:"newPassword"`  
	}

	
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	userCollection := config.GetCollection("users")


	updateFields := bson.M{"updated_at": time.Now()}

	// --- [Case A: Role Change] ---
	if input.Role != "" {
		updateFields["role"] = input.Role
	}

	// --- [Case B: Verify On/Off] ---
	
	if input.Verified != nil {
		updateFields["verified"] = *input.Verified
		
		
		if *input.Verified {
			updateFields["otp"] = "" 
		}
	}

	// --- [Case C: Password Reset] ---
	if input.NewPassword != "" {
		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(input.NewPassword), 14)
		updateFields["password"] = string(hashedPassword)
	}

	
	objID, err := primitive.ObjectIDFromHex(input.TargetUserID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid User ID"})
		return
	}

	update := bson.M{"$set": updateFields}

	result, err := userCollection.UpdateOne(ctx, bson.M{"_id": objID}, update)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user"})
		return
	}
	
	if result.MatchedCount == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":  true,
		"message": "User updated successfully by Admin!",
		"updated_fields": updateFields, 
	})
}



func DeleteUser(c *gin.Context) {
	
	targetUserID := c.Param("id")

	
	requesterID, _ := c.Get("userId")
	requesterRole, _ := c.Get("role")

	if requesterRole != "ADMIN" && requesterID.(string) != targetUserID {
		c.JSON(http.StatusForbidden, gin.H{"error": "You are not allowed to delete this account"})
		return
	}

	var ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	userCollection := config.GetCollection("users")

	objID, err := primitive.ObjectIDFromHex(targetUserID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid User ID"})
		return
	}

	
	update := bson.M{
		"$set": bson.M{
			"is_deleted": true,
			"updated_at": time.Now(),
		},
	}

	result, err := userCollection.UpdateOne(ctx, bson.M{"_id": objID}, update)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete user"})
		return
	}

	if result.MatchedCount == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":  true,
		"message": "User account deactivated successfully",
	})
}



func RefreshToken(c *gin.Context) {
    
    var input struct {
        RefreshToken string `json:"refresh_token" binding:"required"`
    }

    if err := c.ShouldBindJSON(&input); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }

    
    token, err := jwt.Parse(input.RefreshToken, func(token *jwt.Token) (interface{}, error) {
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
        }
        return []byte(os.Getenv("REFRESH_SECRET")), nil
    })

    if err != nil || !token.Valid {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired refresh token"})
        return
    }

    
    claims, ok := token.Claims.(jwt.MapClaims)
    if !ok || !token.Valid {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token claims"})
        return
    }

    userID := claims["user_id"].(string)
    role := claims["role"].(string)

   
    newAccessToken, err := utils.GenerateToken(userID, role, os.Getenv("JWT_SECRET"), time.Hour*1)
    
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not generate new token"})
        return
    }

  
    response := struct {
        Status      bool   `json:"status"`
        AccessToken string `json:"access_token"`
    }{
        Status:      true,
        AccessToken: newAccessToken,
    }

    c.JSON(http.StatusOK, response)
}