package route

import (
	"github.com/RintaroNasu/routetap/api/internal/handler"
	"github.com/labstack/echo/v4"
)

func Register(e *echo.Echo, authHandler handler.AuthHandler, authMiddleware echo.MiddlewareFunc) {
	e.POST("/signup", authHandler.Signup)
	e.POST("/login", authHandler.Login)
	e.GET("/me", authHandler.Me, authMiddleware)
}
