package auth

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/RintaroNasu/routetap/api/internal/httpx"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
)

func TestMiddleware(t *testing.T) {
	secret := "test-secret"
	validManager := NewJWTManager(secret, time.Hour)
	validToken, err := validManager.GenerateToken(1)
	require.NoError(t, err)

	expiredManager := NewJWTManager(secret, -time.Minute)
	expiredToken, err := expiredManager.GenerateToken(1)
	require.NoError(t, err)

	tests := []struct {
		name             string
		authHeader       string
		wantAppError     *httpx.AppError
		wantNextCalled   bool
		wantUserID       uint
		wantUserIDExists bool
	}{
		{
			name:         "【異常系】Authorizationヘッダーがない場合は401を返すこと",
			wantAppError: httpx.Unauthorized("authorization header is required", errors.New("authorization header is missing")),
		},
		{
			name:         "【異常系】Bearer形式不正の場合は401を返すこと",
			authHeader:   "invalid-token",
			wantAppError: httpx.Unauthorized("bearer token is required", errors.New("bearer token is missing")),
		},
		{
			name:         "【異常系】不正tokenの場合は401を返すこと",
			authHeader:   "Bearer invalid-token",
			wantAppError: httpx.Unauthorized("invalid token", errors.New("invalid token")),
		},
		{
			name:         "【異常系】期限切れtokenの場合は401を返すこと",
			authHeader:   "Bearer " + expiredToken,
			wantAppError: httpx.Unauthorized("token has expired", errors.New("token expired")),
		},
		{
			name:             "【正常系】正常tokenの場合はnextが呼ばれuserIDをcontextから取得できること",
			authHeader:       "Bearer " + validToken,
			wantNextCalled:   true,
			wantUserID:       1,
			wantUserIDExists: true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			e := echo.New()
			req := httptest.NewRequest(http.MethodGet, "/me", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			nextCalled := false
			var gotUserID uint
			var gotUserIDExists bool

			h := Middleware(validManager)(func(c echo.Context) error {
				nextCalled = true
				gotUserID, gotUserIDExists = UserIDFromContext(c)
				return c.NoContent(http.StatusNoContent)
			})

			err := h(c)

			if tt.wantAppError != nil {
				require.Error(t, err)
				appErr, ok := err.(*httpx.AppError)
				require.True(t, ok)
				require.Equal(t, tt.wantAppError.Status, appErr.Status)
				require.Equal(t, tt.wantAppError.Code, appErr.Code)
				require.Equal(t, tt.wantAppError.Message, appErr.Message)
				require.False(t, nextCalled)
				return
			}

			require.NoError(t, err)
			require.True(t, nextCalled)
			require.Equal(t, http.StatusNoContent, rec.Code)
			require.Equal(t, tt.wantUserIDExists, gotUserIDExists)
			require.Equal(t, tt.wantUserID, gotUserID)
		})
	}
}

func TestUserIDFromContext(t *testing.T) {
	tests := []struct {
		name       string
		setUserID  bool
		userID     uint
		wantUserID uint
		wantOK     bool
	}{
		{
			name:       "【正常系】userIDが格納されている場合は取得できること",
			setUserID:  true,
			userID:     10,
			wantUserID: 10,
			wantOK:     true,
		},
		{
			name:   "【異常系】userIDが格納されていない場合はfalseを返すこと",
			wantOK: false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			e := echo.New()
			req := httptest.NewRequest(http.MethodGet, "/me", nil)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			if tt.setUserID {
				c.Set(userIDContextKey, tt.userID)
			}

			got, ok := UserIDFromContext(c)

			require.Equal(t, tt.wantOK, ok)
			require.Equal(t, tt.wantUserID, got)
		})
	}
}
