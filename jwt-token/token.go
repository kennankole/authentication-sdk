package jwttoken

import (
	"context"
	"fmt"

	jwt "github.com/golang-jwt/jwt/v5"
)

func (j *JWTConfig) IssueToken(ctx context.Context, claims *CustomClaims) (string, error) {
	newAccessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	token, err := newAccessToken.SignedString(j.SecreteKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign in the access token: %w", err)
	}

	return token, nil
}
