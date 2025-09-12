package middlewares

import (
	"go-auth-paseto/utils"
	"strings"

	"github.com/gofiber/fiber/v2"
)

func AuthMiddleware(c *fiber.Ctx) error {
	authHeader := c.Get("Authorization")
	if authHeader == "" {
		return utils.ErrorResponse(c, fiber.StatusUnauthorized, "Missing authorization header")
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	if tokenString == authHeader {
		return utils.ErrorResponse(c, fiber.StatusUnauthorized, "Invalid token format")
	}

	claims, err := utils.GetTokenClaims(tokenString)
	if err != nil {
		return utils.ErrorResponse(c, fiber.StatusUnauthorized, "Invalid or expired token")
	}

	jti, _ := claims.GetJti()
	exp, _ := claims.GetExpiration()

	isBlacklisted, err := utils.TokenBlacklist.IsBlacklisted(jti)
	if err != nil {
		return utils.ErrorResponse(c, fiber.StatusInternalServerError, "Error checking token status")
	}
	if isBlacklisted {
		return utils.ErrorResponse(c, fiber.StatusUnauthorized, "Token has been invalidated")
	}

	var id uint
	err = claims.Get("id", &id)
	if err != nil {
		return utils.ErrorResponse(c, fiber.StatusUnauthorized, "Invalid ID in token")
	}

	var username string
	err = claims.Get("username", &username)
	if err != nil {
		return utils.ErrorResponse(c, fiber.StatusUnauthorized, "Invalid username in token")
	}

	var role string
	err = claims.Get("role", &role)
	if err != nil {
		return utils.ErrorResponse(c, fiber.StatusUnauthorized, "Invalid role in token")
	}

	c.Locals("id", id)
	c.Locals("username", username)
	c.Locals("role", role)
	c.Locals("jti", jti)
	c.Locals("exp", exp)

	return c.Next()
}
