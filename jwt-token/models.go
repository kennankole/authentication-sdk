package jwttoken

import (
	"github.com/golang-jwt/jwt/v5"
)

type AccessTokenClaims struct {
	UserID string `json:"user_id" validate:"required"`
	Role   string `json:"role" validate:"required"`
	jwt.RegisteredClaims
}

type RefreshTokenClaims struct {
	UserID string `json:"user_id" validate:"required"`
	Role   string `json:"role" validate:"required"`
	JTI    string `json:"jti"`
	jwt.RegisteredClaims
}

type JWTConfig struct {
	SecretKey []byte
}
