package jwttoken

import (
	"context"
	"errors"
	"fmt"
	"slices"

	jwt "github.com/golang-jwt/jwt/v5"
)

func (j *JWTConfig) VerifyJWTToken(ctx context.Context, tokenString string) (*TokenClaims, error) {
	if tokenString == "" {
		return nil, fmt.Errorf("missing refresh token")
	}

	expectedAudience := []string{customersAPI, ridersAPI, merchantsAPI}

	claims := &TokenClaims{}
	_, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}

		return j.SecretKey, nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, fmt.Errorf("refresh token expired: %w", err)
		}

		if errors.Is(err, jwt.ErrTokenNotValidYet) {
			return nil, fmt.Errorf("refresh token not yet valid: %w", err)
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

func isAudienceValid(aud jwt.ClaimStrings, target []string) bool {
	for _, i := range aud {
		if slices.Contains(target, i) {
			return true
		}
	}

	return false
}
