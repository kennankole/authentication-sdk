package jwttoken

import (
	"context"
	"fmt"

	jwt "github.com/golang-jwt/jwt/v5"
)

var SecretKey string

func (j *JWTConfig) VerifyToken(ctx context.Context, tokenString string, claims *CustomClaims) (*jwt.Token, error) {
	token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
		return []byte(j.SecreteKey), nil
	})
	if err != nil {
		return nil, fmt.Errorf("an error occurred: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	return token, nil
}
