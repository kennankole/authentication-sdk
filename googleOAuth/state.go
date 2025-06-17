package googleoauth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// GenereateString generates a secure random string to update the *oauthStateString*
func (o *OAuth2Config) GenerateString(ctx context.Context) (string, error) {
	randomStr := make([]byte, 32)

	_, err := rand.Read(randomStr)
	if err != nil {
		return "", fmt.Errorf("failed to generate OAuth state: %w", err)
	}

	o.State = base64.URLEncoding.EncodeToString(randomStr)

	return o.State, nil
}

// ValidateState validates the OAuth2 state parameter to protect against CSRF
func (o *OAuth2Config) ValidateState(state string) error {
	if o.State != state {
		return fmt.Errorf("invalid OAuth2 state exptected: %s got %s", o.State, state)
	}

	return nil
}
