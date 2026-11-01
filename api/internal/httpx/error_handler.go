package httpx

import (
	"log/slog"
	"net/http"

	"github.com/labstack/echo/v4"
)

type errorResponse struct {
	Error errorDetail `json:"error"`
}

type errorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func HTTPErrorHandler(logger *slog.Logger) echo.HTTPErrorHandler {
	return func(err error, c echo.Context) {
		if c.Response().Committed {
			return
		}

		ctx := c.Request().Context()
		path := c.Path()
		if path == "" {
			path = c.Request().URL.Path
		}

		if appErr, ok := err.(*AppError); ok {
			attrs := []any{
				"status", appErr.Status,
				"code", appErr.Code,
				"path", path,
				"method", c.Request().Method,
			}
			if appErr.Err != nil {
				attrs = append(attrs, "error", appErr.Err)
			}

			if appErr.Status >= http.StatusInternalServerError {
				logger.ErrorContext(ctx, "server_error", attrs...)
			} else {
				logger.WarnContext(ctx, "client_error", attrs...)
			}

			_ = c.JSON(appErr.Status, errorResponse{
				Error: errorDetail{
					Code:    appErr.Code,
					Message: appErr.Message,
				},
			})
			return
		}

		logger.ErrorContext(ctx, "unexpected_error",
			"status", http.StatusInternalServerError,
			"code", "INTERNAL_ERROR",
			"error", err,
			"path", path,
			"method", c.Request().Method,
		)

		_ = c.JSON(http.StatusInternalServerError, errorResponse{
			Error: errorDetail{
				Code:    "INTERNAL_ERROR",
				Message: "internal server error",
			},
		})
	}
}
