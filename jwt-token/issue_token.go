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
func (j *JWTConfig) IssueJWTTokens(ctx context.Context, role, userID string) (*TokenResponse, error) {
	if userID == "" || role == "" {
		return nil, fmt.Errorf("missing user id or role or both: user/role cannot be empty")
	}

	currentTime := time.Now()
	accessTokenClaims := TokenClaims{
		UserID: userID,
		Role:   role,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    defaultIssuer,
			ExpiresAt: jwt.NewNumericDate(currentTime.Add(15 * time.Minute)),
			Audience:  []string{customersAPI, ridersAPI, merchantsAPI},
			NotBefore: jwt.NewNumericDate(currentTime.Add(3 * time.Second)),
			IssuedAt:  jwt.NewNumericDate(currentTime),
			Subject:   userID,
			ID:        uuid.New().String(),
		},
	}
	newAccessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessTokenClaims)

	accessToken, err := newAccessToken.SignedString(j.SecretKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign the access token: %w", err)
	}

	refreshTokenClaims := TokenClaims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    defaultIssuer,
			ExpiresAt: jwt.NewNumericDate(currentTime.Add(7 * 24 * time.Hour)),
			Audience:  []string{defaultIssuer},
			NotBefore: jwt.NewNumericDate(currentTime.Add(3 * time.Second)),
			IssuedAt:  jwt.NewNumericDate(currentTime),
			Subject:   userID,
			ID:        uuid.New().String(),
		},
	}
	newRefreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshTokenClaims)
	refreshToken, err := newRefreshToken.SignedString(j.SecretKey)

	if err != nil {
		return nil, fmt.Errorf("failed to sign the refresh token: %w", err)
	}

	results := &TokenResponse{
		AccessTokenClaims:  &accessTokenClaims,
		AccessToken:        accessToken,
		RefreshTokenClaims: &refreshTokenClaims,
		RefreshToken:       refreshToken,
	}

	return results, nil
}

// GenerateOAuthState generates OAuth2 state
func (j *JWTConfig) GenerateOAuthState(ctx context.Context, userID *string, purpose, userType string) (*TokenResponse, error) {
	var subject string

	if userID != nil {
		subject = *userID
	}

	verifier, err := j.GenerateCodeVerifier()
	if err != nil {
		return nil, err
	}

	oauthTokenClaims := &TokenClaims{
		UserID:       subject,
		Purpose:      purpose,
		Role:         userType,
		CodeVerifier: verifier,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
			Subject:   subject,
			ID:        uuid.New().String(),
		},
	}

	oauthStateToken := jwt.NewWithClaims(jwt.SigningMethodHS256, oauthTokenClaims)

	token, err := oauthStateToken.SignedString(j.OAuthStateSecretKey)
	if err != nil {
		return nil, err
	}

	results := &TokenResponse{
		StateToken:       token,
		OAuthStateClaims: oauthTokenClaims,
	}

	return results, nil
}
