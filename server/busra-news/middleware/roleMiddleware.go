package middleware

import (
	"net/http"
	"github.com/gin-gonic/gin"
)


func RoleMiddleware(requiredRole string) gin.HandlerFunc {
	return func(c *gin.Context) {
		
		userRole, exists := c.Get("role")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			c.Abort()
			return
		}

		
		if userRole.(string) != requiredRole {
			c.JSON(http.StatusForbidden, gin.H{"error": "Access denied. Admins only."})
			c.Abort()
			return
		}

		
		c.Next()
	}
}