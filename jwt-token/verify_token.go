package jwttoken

import (
	"context"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

func (j *JWTConfig) VerifyJWTToken(ctx context.Context, tokenString string) (*TokenClaims, error) {
	if tokenString == "" {
		return nil, fmt.Errorf("missing access token")
	}

	expectedAudience := []string{j.CustomerAudience, j.RiderAudience, j.CustomerAudience}

	return j.verifyToken(ctx, tokenString, j.Host, expectedAudience, true, true, j.SecretKey)
}

func (j *JWTConfig) VerifyJWTRefreshToken(ctx context.Context, refreshToken string) (*TokenClaims, error) {
	if refreshToken == "" {
		return nil, fmt.Errorf("missing refresh token")
	}

	expectedAudience := []string{j.Host}

	return j.verifyToken(ctx, refreshToken, j.Host, expectedAudience, true, true, j.SecretKey)
}

func (j *JWTConfig) VerifyOAuthStateJWTToken(ctx context.Context, token string) (*TokenClaims, error) {
	if token == "" {
		return nil, fmt.Errorf("missing OAuthState token")
	}

	return j.verifyToken(ctx, token, j.Host, nil, false, false, j.OAuthStateSecretKey)
}

func (j *JWTConfig) VerifyCartClaimToken(ctx context.Context, token string) (*CartKeyClaims, error) {
	if token == "" {
		return nil, fmt.Errorf("missing cart token")
	}

	cartClaims := &CartKeyClaims{}
	cartToken, err := jwt.ParseWithClaims(token, cartClaims, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.((*jwt.SigningMethodHMAC)); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}

		return j.SecretKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse cart ID token: %w", err)
	}

	claims, ok := cartToken.Claims.(*CartKeyClaims)
	if !ok || !cartToken.Valid {
		return nil, fmt.Errorf("invalid cart token")
	}

	return claims, nil
}
