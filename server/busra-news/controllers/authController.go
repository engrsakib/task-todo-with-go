package controllers

import (
	"context"
	"fmt"
	"log"
	"math"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/engrsakib/news-with-go/config"
	"github.com/engrsakib/news-with-go/models"
	"github.com/engrsakib/news-with-go/utils"
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/gomail.v2"
)


type LoginRequest struct {
	Email    string `json:"email" binding:"required,email" example:"user@example.com"`
	Password string `json:"password" binding:"required" example:"123456"`
}

type VerifyOTPRequest struct {
	Email string `json:"email" binding:"required,email" example:"user@example.com"`
	OTP   string `json:"otp" binding:"required" example:"1234"`
}

type ResendOTPRequest struct {
	Email string `json:"email" binding:"required,email" example:"user@example.com"`
}

type ResetPasswordRequest struct {
	Email       string `json:"email" binding:"required,email" example:"user@example.com"`
	OTP         string `json:"otp" binding:"required" example:"1234"`
	NewPassword string `json:"newPassword" binding:"required,min=6" example:"newpassword123"`
}

type ChangePasswordRequest struct {
	CurrentPassword string `json:"currentPassword" binding:"required"`
	NewPassword     string `json:"newPassword" binding:"required,min=6"`
	RetypePassword  string `json:"retypePassword" binding:"required,eqfield=NewPassword"`
}

type UpdateUserRequest struct {
	Name string `json:"name" binding:"required" example:"Sakib Khan"`
}

type AdminUpdateUserRequest struct {
	TargetUserID string `json:"targetUserId" binding:"required" example:"65b1a5e2..." `
	Role         string `json:"role" example:"ADMIN"`
	Verified     *bool  `json:"verified" example:"true"`
	NewPassword  string `json:"newPassword" example:"admin123456"`
}

// RegisterUser godoc
// @Summary      Register a new user
// @Description  Creates a new user account and sends a 4-digit OTP to the user's email
// @Tags         Auth
// @Accept       json
// @Produce      json
// @Param        user  body      models.User  true  "User Registration Data"
// @Success      201   {object}  map[string]interface{}
// @Router       /auth/register [post]

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

// ResendOTP godoc
// @Summary      Resend OTP
// @Description  Sends a new OTP for accounts that have not completed verification
// @Tags         Auth
// @Accept       json
// @Produce      json
// @Param        input  body      ResendOTPRequest  true  "User Email"
// @Success      200    {object}  map[string]interface{}
// @Router       /auth/resend-otp [post]
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

// LoginAsUser godoc
// @Summary      user login
// @Description  Login with email and password to obtain Access and Refresh tokens
// @Tags         Auth
// @Accept       json
// @Produce      json
// @Param        credentials  body  LoginRequest  true  "Login Credentials"
// @Success      200          {object}  map[string]interface{}
// @Router       /auth/login [post]
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

	accessToken, refreshToken, err := utils.GenerateTokens(user.ID.Hex(), user.Name, user.Email, user.Role)
	
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate tokens"})
		return
	}

	// ৬. রেসপন্স পাঠানো
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

// VerifyOTP godoc
// @Summary      Verify account
// @Description  Activate account using OTP sent to email
// @Tags         Auth
// @Accept       json
// @Produce      json
// @Param        verify  body      VerifyOTPRequest  true  "Verification Data"
// @Success      200     {object}  map[string]interface{}
// @Router       /auth/verify [post]
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

// ForgotPassword godoc
// @Summary      Reset password
// @Description  Sends an OTP to the email for password reset
// @Tags         Auth
// @Accept       json
// @Produce      json
// @Param        forgot  body      ResendOTPRequest  true  "User Email"
// @Success      200     {object}  map[string]interface{}
// @Router       /auth/forgot-password [post]
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

// ResetPassword godoc
// @Summary      Reset password using OTP
// @Description  Verify OTP and set a new password
// @Tags         Auth
// @Accept       json
// @Produce      json
// @Param        reset  body      ResetPasswordRequest  true  "Reset Data"
// @Success      200    {object}  map[string]interface{}
// @Router       /auth/reset-password [post]
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

// GetProfile godoc
// @Summary      Get current user profile
// @Description  Retrieve profile details of the logged-in user
// @Tags         Users
// @Security     BearerAuth
// @Produce      json
// @Success      200   {object}  map[string]interface{}
// @Router       /auth/me [get]
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


// ChangePassword godoc
// @Summary      Change password (while logged in)
// @Description  Set a new password using the current password
// @Tags         Users
// @Security     BearerAuth
// @Accept       json
// @Produce      json
// @Param        change  body      ChangePasswordRequest  true  "Change Password Data"
// @Success      200     {object}  map[string]interface{}
// @Router       /auth/change-password [post]
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



// UpdateUser godoc
// @Summary      Update user name
// @Description  Users can update their own name
// @Tags         Users
// @Security     BearerAuth
// @Accept       json
// @Produce      json
// @Param        update  body      UpdateUserRequest  true  "Update Name"
// @Success      200     {object}  map[string]interface{}
// @Router       /auth/update-profile [patch]
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


// AdminUpdateUser godoc
// @Summary      Admin update user details
// @Description  Admin can change any user's role, verification status, or password
// @Tags         Admin
// @Security     BearerAuth
// @Accept       json
// @Produce      json
// @Param        adminUpdate  body      AdminUpdateUserRequest  true  "Admin Update Data"
// @Success      200          {object}  map[string]interface{}
// @Router       /auth/admin/update-user [patch]
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


// DeleteUser godoc
// @Summary      Deactivate user account
// @Description  Soft delete a user account by ID (Admin or Self)
// @Tags         Admin
// @Security     BearerAuth
// @Param        id    path      string  true  "User ID"
// @Success      200   {object}  map[string]interface{}
// @Router       /auth/admin/delete-user/{id} [delete]
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


// RefreshToken godoc
// @Summary      Refresh access token
// @Description  Obtain a new access token using a refresh token
// @Tags         Auth
// @Security     BearerAuth
// @Produce      json
// @Success      200  {object}  map[string]interface{}
// @Router       /auth/refresh-token [post]
func RefreshToken(c *gin.Context) {
	// ১. হেডার চেক
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Authorization header is required"})
		return
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Authorization header format must be Bearer {token}"})
		return
	}
	refreshTokenString := parts[1]

	// ২. টোকেন ভ্যালিডেট (রিফ্রেশ সিক্রেট দিয়ে)
	claims, err := utils.ValidateRefreshToken(refreshTokenString) // আপনার তৈরি করা নতুন ভ্যালিডেট ফাংশন
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired refresh token"})
		return
	}

	// ৩. 🛡️ ডাটাবেস থেকে ফ্রেশ ডাটা আনা (এটাই আসল ফিক্স)
	// টোকেনের ফাঁকা ডাটার ওপর ভরসা না করে আমরা আইডি দিয়ে ডাটাবেস খুঁজব
	var ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	userCollection := config.GetCollection("users")
	var user models.User

	// claims.UserID স্ট্রিং থেকে অবজেক্ট আইডিতে কনভার্ট (যদি আপনার মডেলে আইডি ObjectID হয়)
	objID, err := primitive.ObjectIDFromHex(claims.UserID)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid user ID in token"})
		return
	}

	// ডাটাবেসে ইউজার খোঁজা
	err = userCollection.FindOne(ctx, bson.M{"_id": objID}).Decode(&user)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
		return
	}

	// ৪. সিকিউরিটি চেক (ইউজার ব্যান বা ডিলিট কিনা)
	if user.Is_Deleted {
		c.JSON(http.StatusForbidden, gin.H{"error": "User account is deactivated"})
		return
	}

	// ৫. নতুন টোকেন জেনারেট (ডাটাবেসের রিয়েল ডাটা দিয়ে) ✅
	// লক্ষ্য করুন: এখানে আমরা user.Name, user.Email, user.Role ডাটাবেস থেকে দিচ্ছি
	newAccessToken, newRefreshToken, err := utils.GenerateTokens(user.ID.Hex(), user.Name, user.Email, user.Role)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not generate new token"})
		return
	}

	// ৬. রেসপন্স
	c.JSON(http.StatusOK, gin.H{
		"status":        true,
		"access_token":  newAccessToken,
		"refresh_token": newRefreshToken,
	})
}

// GetAllUsers godoc
// @Summary      Get all users (Admin Only)
// @Description  Retrieve a paginated list of all non-deleted users
// @Tags         Admin
// @Security     BearerAuth
// @Param        page    query     int     false  "Page number"
// @Param        limit   query     int     false  "Items per page"
// @Param        search  query     string  false  "Search by name or email"
// @Success      200     {object}  map[string]interface{}
// @Router       /auth/admin/users [get]
func GetAllUsers(c *gin.Context) {
    
    page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
    limit, _ := strconv.Atoi(c.DefaultQuery("limit", "10"))
    searchTerm := c.Query("search") 

    if page < 1 { page = 1 }
    if limit < 1 { limit = 10 }

    skip := (page - 1) * limit

    var ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()

    userCollection := config.GetCollection("users")

  
    filter := bson.M{"is_deleted": false}

    
    if searchTerm != "" {
        filter["$or"] = []bson.M{
            {"name": bson.M{"$regex": searchTerm, "$options": "i"}},  
            {"email": bson.M{"$regex": searchTerm, "$options": "i"}},
        }
    }


    findOptions := options.Find()
    findOptions.SetSkip(int64(skip))
    findOptions.SetLimit(int64(limit))
    findOptions.SetSort(bson.D{{Key: "created_at", Value: -1}}) 
    findOptions.SetProjection(bson.M{"password": 0}) 

    
    cursor, err := userCollection.Find(ctx, filter, findOptions)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Error fetching users"})
        return
    }
    defer cursor.Close(ctx)

   
    users := make([]bson.M, 0)
    
    if err = cursor.All(ctx, &users); err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Error decoding users"})
        return
    }

 
    total, _ := userCollection.CountDocuments(ctx, filter)

  
    c.JSON(http.StatusOK, gin.H{
        "status": true,
        "data":   users,
        "meta": gin.H{
            "total":       total,
            "page":        page,
            "limit":       limit,
            "total_pages": int(math.Ceil(float64(total) / float64(limit))),
        },
    })
}