package middleware

import (
	"net/http"
	"github.com/gin-gonic/gin"
	"strings"
)


func RoleMiddleware(requiredRole string) gin.HandlerFunc {
    return func(c *gin.Context) {
        
        userRole, exists := c.Get("role")
        if !exists {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
            c.Abort()
            return
        }

        // ২. strings.EqualFold ব্যবহার করুন
        // এটি "Admin", "admin", "ADMIN" সব কিছুকেই সমান মনে করবে
        if !strings.EqualFold(userRole.(string), requiredRole) {
            c.JSON(http.StatusForbidden, gin.H{"error": "Access denied. Admins only."})
            c.Abort()
            return
        }

        c.Next()
    }
}