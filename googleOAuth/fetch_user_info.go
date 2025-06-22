package googleoauth

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"slices"
	"time"

	"github.com/MicahParks/keyfunc/v2"
	"github.com/golang-jwt/jwt/v5"
)

// InitGoogleAuthService is used to fetch Google public cryptographic keys.
func InitGoogleAuthService(ctx context.Context, clientID string) (*GoogleAuthService, error) {
	GoogleJWKSURL := "https://www.googleapis.com/oauth2/v3/certs"

	options := keyfunc.Options{
		RefreshErrorHandler: func(err error) {
			log.Printf("ERROR: Failed to refresh Google JWKS: %v", err)
		},
		RefreshInterval:  time.Hour,
		RefreshRateLimit: time.Minute * 5,
		Client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}

	googleAuthService, err := keyfunc.Get(GoogleJWKSURL, options)
	if err != nil {
		return nil, fmt.Errorf("failed to get Google JWKS from %s: %w", GoogleJWKSURL, err)
	}

	results := &GoogleAuthService{
		GoogleJWKS: googleAuthService,
		ClientID:   clientID,
	}

	return results, nil
}

func (o *GoogleAuthService) Close() {
	if o.GoogleJWKS != nil {
		o.GoogleJWKS.EndBackground()
	}
}

// GetUserInfo uses a token ID to fetch user details.
func (o *GoogleAuthService) GetUserInfo(ctx context.Context, tokenID string) (*TokenIDClaims, error) {
	claims := TokenIDClaims{}

	currentTime := time.Now()

	if o.GoogleJWKS == nil {
		return nil, fmt.Errorf("JWKS Keyfunc is nil")
	}

	idToken, err := jwt.ParseWithClaims(
		tokenID, &claims,
		o.GoogleJWKS.Keyfunc,
		jwt.WithAudience(o.ClientID),
	)

	if err != nil {
		return nil, fmt.Errorf("failed to validate token ID: %w", err)
	}

	if claims.ExpiresAt != nil && currentTime.After(claims.ExpiresAt.Time) {
		return nil, fmt.Errorf("token ID expired at %s", claims.ExpiresAt.Time)
	}

	if claims.IssuedAt != nil && currentTime.Before(claims.IssuedAt.Time) {
		return nil, fmt.Errorf("token ID cannot be used before issued: %s", claims.IssuedAt.Time)
	}

	if claims.NotBefore != nil && currentTime.Before(claims.NotBefore.Time) {
		return nil, fmt.Errorf("token not valid before: %s", claims.NotBefore.Time)
	}

	if !idToken.Valid {
		return nil, fmt.Errorf("invalid token ID")
	}

	expectedIssuers := []string{"https://accounts.google.com", "accounts.google.com"}

	isIssuerValid := slices.Contains(expectedIssuers, claims.Issuer)
	if !isIssuerValid {
		return nil, fmt.Errorf("token issuer mismatch: expected one of %v, got '%s'", expectedIssuers, claims.Issuer)
	}

	if !claims.EmailVerified {
		return nil, fmt.Errorf("email not verified for this token")
	}

	return &claims, nil
}
