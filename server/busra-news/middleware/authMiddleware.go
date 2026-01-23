package middleware

import (
	"net/http"
	"strings"

	"github.com/engrsakib/news-with-go/utils"
	"github.com/gin-gonic/gin"
)


func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header is missing"})
			c.Abort()
			return
		}

		
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == authHeader {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token format (Missing Bearer)"})
			c.Abort()
			return
		}

		
		claims, err := utils.ValidateToken(tokenString)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired token"})
			c.Abort()
			return
		}

		
		c.Set("userId", claims.UserID)
		c.Set("email", claims.Email) 
		c.Set("role", claims.Role)
		c.Set("name", claims.Name)   

		
		c.Next()
	}
}