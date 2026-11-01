package auth

import (
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type JWTManager struct {
	secretKey []byte
	ttl       time.Duration
}

func NewJWTManager(secret string, ttl time.Duration) *JWTManager {
	return &JWTManager{
		secretKey: []byte(secret),
		ttl:       ttl,
	}
}

func (m *JWTManager) GenerateToken(userID uint) (string, error) {
	now := time.Now()

	claims := jwt.MapClaims{
		"sub": fmt.Sprintf("%d", userID),
		"exp": now.Add(m.ttl).Unix(),
		"iat": now.Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	signedToken, err := token.SignedString(m.secretKey)
	if err != nil {
		return "", fmt.Errorf("sign token: %w", err)
	}

	return signedToken, nil
}

func (m *JWTManager) ParseToken(tokenString string) (uint, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		if token.Method != jwt.SigningMethodHS256 {
			return nil, fmt.Errorf("unexpected signing method: %s", token.Method.Alg())
		}

		return m.secretKey, nil
	}, jwt.WithExpirationRequired())
	if err != nil {
		return 0, fmt.Errorf("parse token: %w", err)
	}

	if !token.Valid {
		return 0, errors.New("token is invalid")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return 0, errors.New("token claims are invalid")
	}

	sub, ok := claims["sub"].(string)
	if !ok || sub == "" {
		return 0, errors.New("sub claim is missing")
	}

	userID, err := strconv.ParseUint(sub, 10, strconv.IntSize)
	if err != nil {
		return 0, fmt.Errorf("parse sub claim: %w", err)
	}

	if userID == 0 {
		return 0, errors.New("sub claim must be a positive user ID")
	}
	return uint(userID), nil
}
