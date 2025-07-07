package jwttoken

import (
	"context"
	"fmt"
)

func (j *JWTConfig) VerifyJWTToken(ctx context.Context, tokenString string) (*TokenClaims, error) {
	if tokenString == "" {
		return nil, fmt.Errorf("missing access token")
	}

	expectedAudience := []string{customersAPI, ridersAPI, merchantsAPI}

	return j.verifyToken(ctx, tokenString, defaultIssuer, expectedAudience, true, true, j.SecretKey)
}

func (j *JWTConfig) VerifyJWTRefreshToken(ctx context.Context, refreshToken string) (*TokenClaims, error) {
	if refreshToken == "" {
		return nil, fmt.Errorf("missing refresh token")
	}

	expectedAudience := []string{defaultIssuer}

	return j.verifyToken(ctx, refreshToken, defaultIssuer, expectedAudience, true, true, j.SecretKey)
}

func (j *JWTConfig) VerifyOAuthStateJWTToken(ctx context.Context, token string) (*TokenClaims, error) {
	if token == "" {
		return nil, fmt.Errorf("missing OAuthState token")
	}

	return j.verifyToken(ctx, token, defaultIssuer, nil, false, false, j.OAuthStateSecretKey)
}
