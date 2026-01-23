package middleware

import (
	"net/http"
	"strings"

	"github.com/engrsakib/news-with-go/utils"
	"github.com/gin-gonic/gin"
)

// AuthMiddleware - চেক করবে রিকোয়েস্টে ভ্যালিড টোকেন আছে কিনা
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// ১. হেডার থেকে টোকেন বের করা
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header is missing"})
			c.Abort()
			return
		}

		// ২. "Bearer " অংশটি বাদ দেওয়া
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == authHeader {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token format (Missing Bearer)"})
			c.Abort()
			return
		}

		// ৩. টোকেন ভ্যালিডেট করা (Utils ব্যবহার করে)
		claims, err := utils.ValidateToken(tokenString)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired token"})
			c.Abort()
			return
		}

		// ৪. সব ঠিক থাকলে ইউজারের তথ্য কন্টেক্সটে সেট করা
		// যাতে পরের কন্ট্রোলার বুঝতে পারে কে রিকোয়েস্ট করেছে
		c.Set("userId", claims.UserID)
		c.Set("role", claims.Role)

		// ৫. পরের স্টেপে যাও
		c.Next()
	}
}