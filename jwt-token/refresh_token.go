package jwttoken

import (
	"context"
	"errors"
	"fmt"

	jwt "github.com/golang-jwt/jwt/v5"
)

// VerifyJWTRefreshToken is used to verify the refresh token
func (j *JWTConfig) VerifyJWTRefreshToken(ctx context.Context, refreshToken string) (*TokenClaims, error) {
	if refreshToken == "" {
		return nil, fmt.Errorf("missing access token")
	}

	expectedIssuer := defaultIssuer
	expectedAudience := []string{expectedIssuer}

	claims := &TokenClaims{}

	_, err := jwt.ParseWithClaims(refreshToken, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}

		return j.SecretKey, nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, fmt.Errorf("token expired: %w", err)
		}

		if errors.Is(err, jwt.ErrTokenNotValidYet) {
			return nil, fmt.Errorf("token not yet valid: %w", err)
		}

		return nil, fmt.Errorf("an error occurred: %w", err)
	}

	issuer, err := claims.GetIssuer()
	if err != nil {
		return nil, fmt.Errorf("unable to get refresh token issuer from claims: %w", err)
	}

	if issuer != defaultIssuer {
		return nil, fmt.Errorf("invalid issuer in claims")
	}

	aud, err := claims.GetAudience()
	if err != nil {
		return nil, fmt.Errorf("failed to get audience %w", err)
	}

	if !isAudienceValid(aud, expectedAudience) {
		return nil, fmt.Errorf("invalid refresh token audience")
	}

	return claims, nil
}
