package auth

import (
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

func TestJWTManager_GenerateToken(t *testing.T) {
	tests := []struct {
		name    string
		secret  string
		ttl     time.Duration
		userID  uint
		wantErr bool
	}{
		{
			name:   "【正常系】tokenを生成できること",
			secret: "test-secret",
			ttl:    time.Hour,
			userID: 1,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			manager := NewJWTManager(tt.secret, tt.ttl)

			got, err := manager.GenerateToken(tt.userID)

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.NotEmpty(t, got)
			require.Len(t, strings.Split(got, "."), 3)
		})
	}
}

func TestJWTManager_ParseToken(t *testing.T) {
	secret := "test-secret"
	manager := NewJWTManager(secret, time.Hour)

	validToken, err := manager.GenerateToken(10)
	require.NoError(t, err)

	expiredToken, err := NewJWTManager(secret, -time.Minute).GenerateToken(10)
	require.NoError(t, err)

	missingSubToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	}).SignedString([]byte(secret))
	require.NoError(t, err)

	invalidSubToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "not-number",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	}).SignedString([]byte(secret))
	require.NoError(t, err)

	wrongAlgToken, err := jwt.NewWithClaims(jwt.SigningMethodHS384, jwt.MapClaims{
		"sub": "10",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	}).SignedString([]byte(secret))
	require.NoError(t, err)

	tests := []struct {
		name            string
		token           string
		wantUserID      uint
		wantErrContains string
	}{
		{
			name:       "【正常系】正常なtokenを解析できること",
			token:      validToken,
			wantUserID: 10,
		},
		{
			name:            "【異常系】壊れたtokenの場合はparse tokenエラーになること",
			token:           "invalid-token",
			wantErrContains: "parse token",
		},
		{
			name:            "【異常系】期限切れtokenの場合はparse tokenエラーになること",
			token:           expiredToken,
			wantErrContains: "parse token",
		},
		{
			name:            "【異常系】sub claimがない場合はsub claim is missingエラーになること",
			token:           missingSubToken,
			wantErrContains: "sub claim is missing",
		},
		{
			name:            "【異常系】sub claimが数値でない場合はparse sub claimエラーになること",
			token:           invalidSubToken,
			wantErrContains: "parse sub claim",
		},
		{
			name:            "【異常系】署名方式が想定外の場合はunexpected signing methodエラーになること",
			token:           wrongAlgToken,
			wantErrContains: "unexpected signing method",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got, err := manager.ParseToken(tt.token)

			switch {
			case tt.wantErrContains != "":
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.wantErrContains)
			default:
				require.NoError(t, err)
				require.Equal(t, tt.wantUserID, got)
			}
		})
	}
}

func TestJWTManager_RejectsMissingExpiryZeroIDAndWrongSignature(t *testing.T) {
	manager := NewJWTManager("test-secret", time.Hour)
	noExpiry, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": "1"}).SignedString([]byte("test-secret"))
	require.NoError(t, err)
	zeroID, err := manager.GenerateToken(0)
	require.NoError(t, err)
	wrongSignature, err := NewJWTManager("different-secret", time.Hour).GenerateToken(1)
	require.NoError(t, err)
	for _, token := range []string{noExpiry, zeroID, wrongSignature} {
		_, err := manager.ParseToken(token)
		require.Error(t, err)
	}
}
