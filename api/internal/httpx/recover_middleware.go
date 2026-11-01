package httpx

import (
	"fmt"
	"runtime/debug"

	"github.com/labstack/echo/v4"
)

func RecoverMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) (err error) {
			defer func() {
				if recovered := recover(); recovered != nil {
					err = Internal(
						"internal server error",
						fmt.Errorf("panic recovered: %v: %s", recovered, debug.Stack()),
					)
				}
			}()
			return next(c)
		}
	}
}
