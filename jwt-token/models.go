package jwttoken

import (
	"github.com/golang-jwt/jwt/v5"
)

type TokenClaims struct {
	UserID string `json:"user_id" validate:"required"`
	Role   string `json:"role" validate:"required"`
	jwt.RegisteredClaims
}

type JWTConfig struct {
	SecretKey []byte
}

type TokenResponse struct {
	AccessTokenClaims  *TokenClaims
	RefreshTokenClaims *TokenClaims
	AccessToken        string
	RefreshToken       string
}
