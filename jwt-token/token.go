package jwttoken

import (
	"context"
	"fmt"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const defaultIssuer = "http://localhost:9000/v1/auth"

const (
	customersAPI = "customers-services"
	ridersAPI    = "riders-services"
	merchantsAPI = "merchants-service"
)

// IssueToken issues access and refresh tokens
func (j *JWTConfig) IssueJWTTokens(ctx context.Context, role, userID string) (*string, *string, error) {
	if userID == "" || role == "" {
		return nil, nil, fmt.Errorf("missing user id or role or both: user/role cannot be empty")
	}

	currentTime := time.Now()
	tokenClaims := AccessTokenClaims{
		UserID: userID,
		Role:   role,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    defaultIssuer,
			ExpiresAt: jwt.NewNumericDate(currentTime.Add(15 * time.Minute)),
			Audience:  []string{customersAPI, ridersAPI, merchantsAPI},
			NotBefore: jwt.NewNumericDate(currentTime.Add(3 * time.Second)),
			IssuedAt:  jwt.NewNumericDate(currentTime),
			Subject:   userID,
		},
	}
	newAccessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, tokenClaims)

	token, err := newAccessToken.SignedString(j.SecretKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to sign the access token: %w", err)
	}

	refreshTokenClaims := RefreshTokenClaims{
		UserID: userID,
		Role:   role,
		JTI:    uuid.New().String(),
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    defaultIssuer,
			ExpiresAt: jwt.NewNumericDate(currentTime.Add(7 * 24 * time.Hour)),
			Audience:  []string{defaultIssuer},
			NotBefore: jwt.NewNumericDate(currentTime.Add(3 * time.Second)),
			IssuedAt:  jwt.NewNumericDate(currentTime),
			Subject:   userID,
		},
	}
	newRefreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshTokenClaims)
	refreshToken, err := newRefreshToken.SignedString(j.SecretKey)

	if err != nil {
		return nil, nil, fmt.Errorf("failed to sign the refresh token: %w", err)
	}

	return &token, &refreshToken, nil
}
