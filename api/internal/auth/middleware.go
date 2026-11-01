package auth

import (
	"errors"
	"strings"

	"github.com/RintaroNasu/routetap/api/internal/httpx"
	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
)

const userIDContextKey = "auth_user_id"

func Middleware(jwtManager *JWTManager) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			authHeader := c.Request().Header.Get("Authorization")
			if authHeader == "" {
				return httpx.Unauthorized("authorization header is required", errors.New("authorization header is missing"))
			}

			token := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
			if token == "" || token == authHeader {
				return httpx.Unauthorized("bearer token is required", errors.New("bearer token is missing"))
			}

			userID, err := jwtManager.ParseToken(token)
			if err != nil {
				switch {
				case errors.Is(err, jwt.ErrTokenExpired):
					return httpx.Unauthorized("token has expired", err)
				default:
					return httpx.Unauthorized("invalid token", err)
				}
			}

			c.Set(userIDContextKey, userID)
			return next(c)
		}
	}
}

func UserIDFromContext(c echo.Context) (uint, bool) {
	userID, ok := c.Get(userIDContextKey).(uint)
	return userID, ok
}
