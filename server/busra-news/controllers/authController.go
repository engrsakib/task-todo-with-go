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
	"github.com/gin-gonic/gin"
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