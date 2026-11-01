package httpx

import (
	"fmt"
	"net/http"
)

type AppError struct {
	Status  int
	Code    string
	Message string
	Err     error
}

func (e *AppError) Error() string {
	if e.Err == nil {
		return fmt.Sprintf("%s: %s", e.Code, e.Message)
	}

	return fmt.Sprintf("%s: %s: %v", e.Code, e.Message, e.Err)
}

func (e *AppError) Unwrap() error {
	return e.Err
}

func InvalidRequest(msg string, err error) *AppError {
	return &AppError{
		Status:  http.StatusBadRequest,
		Code:    "INVALID_REQUEST",
		Message: msg,
		Err:     err,
	}
}

func Unauthorized(msg string, err error) *AppError {
	return &AppError{
		Status:  http.StatusUnauthorized,
		Code:    "UNAUTHORIZED",
		Message: msg,
		Err:     err,
	}
}

func NotFound(msg string, err error) *AppError {
	return &AppError{
		Status:  http.StatusNotFound,
		Code:    "NOT_FOUND",
		Message: msg,
		Err:     err,
	}
}

func Conflict(msg string, err error) *AppError {
	return &AppError{
		Status:  http.StatusConflict,
		Code:    "CONFLICT",
		Message: msg,
		Err:     err,
	}
}

func Internal(msg string, err error) *AppError {
	return &AppError{
		Status:  http.StatusInternalServerError,
		Code:    "INTERNAL_ERROR",
		Message: msg,
		Err:     err,
	}
}
