package jwttoken

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// isAudienceValid: checks the validity of audience in JWT claims
func isAudienceValid(aud jwt.ClaimStrings, target []string) bool {
	for _, i := range aud {
		if slices.Contains(target, i) {
			return true
		}
	}

	return false
}

// verifyToken: is a JWT agnostic method to verify JWT tokens
func (j *JWTConfig) verifyToken(
	_ context.Context,
	tokenString string,
	expectedIssuer string,
	expectedAudience []string,
	validateAudience bool,
	validateIssuer bool,
	signingKey []byte,
) (*TokenClaims, error) {
	if tokenString == "" {
		return nil, fmt.Errorf("missing token")
	}

	claims := &TokenClaims{}

	_, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.((*jwt.SigningMethodHMAC)); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}

		return signingKey, nil
	})

	if err != nil {
		switch {
		case errors.Is(err, jwt.ErrTokenExpired):
			return nil, fmt.Errorf("token expired: %w", err)
		case errors.Is(err, jwt.ErrTokenNotValidYet):
			return nil, fmt.Errorf("token not yet valid: %w", err)
		default:
			return nil, fmt.Errorf("failed to parse token: %w", err)
		}
	}

	if validateIssuer {
		issuer, err := claims.GetIssuer()
		if err != nil {
			return nil, fmt.Errorf("unable to get issuer from claims: %w", err)
		}

		if issuer != expectedIssuer {
			return nil, fmt.Errorf("invalid issuer: expected %s, got %s", expectedIssuer, issuer)
		}
	}

	if validateAudience {
		aud, err := claims.GetAudience()
		if err != nil {
			return nil, fmt.Errorf("unable to get audience: %w", err)
		}

		if !isAudienceValid(aud, expectedAudience) {
			return nil, fmt.Errorf("invalid audience: expected one of %v, got %v", expectedAudience, aud)
		}
	}

	return claims, nil
}

func (j *JWTConfig) GenerateCodeVerifier() (string, error) {
	code := make([]byte, 32)

	_, err := rand.Read(code)
	if err != nil {
		return "", fmt.Errorf("unable to generate code verifier: %w", err)
	}

	verifier := strings.TrimRight(base64.URLEncoding.EncodeToString(code), "=")

	return verifier, nil
}
