package jwttoken

import (
	"github.com/golang-jwt/jwt/v5"
)

type TokenClaims struct {
	UserID       string `json:"user_id,omitempty"`
	Role         string `json:"role,omitempty"`
	Purpose      string `json:"purpose,omitempty"`
	CodeVerifier string `json:"code_verifier,omitempty"`
	jwt.RegisteredClaims
}

type JWTConfig struct {
	SecretKey           []byte
	OAuthStateSecretKey []byte
	Host                string `json:"host,omitempty"`
}

type TokenResponse struct {
	AccessTokenClaims  *TokenClaims
	RefreshTokenClaims *TokenClaims
	OAuthStateClaims   *TokenClaims
	StateToken         string
	AccessToken        string
	RefreshToken       string
}

type CartKeyClaims struct {
	jwt.RegisteredClaims
	CartID string `json:"cart_id,omitempty"`
}

type SignedCartClaims struct {
	CartToken string `json:"cart_token,omitempty"`
	Claims    *CartKeyClaims
}
