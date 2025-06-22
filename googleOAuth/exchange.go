package googleoauth

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/kennankole/authentication-sdk/request"
)

// Exchange: exchanges the authorization code for an access token:
func (o *OAuth2Config) Exchange(ctx context.Context, code *string) (*TokenResponse, error) {
	if code == nil {
		return nil, fmt.Errorf("code cannot be empty")
	}

	if o.CodeVerifier == "" {
		return nil, fmt.Errorf("could not find code verifier which is required in the OAuth2.1 flow")
	}

	input := &OAuth2Config{
		ClientID:     o.ClientID,
		ClientSecret: o.ClientSecret,
		CallbackURL:  o.CallbackURL,
		GrantType:    o.GrantType,
		TokenURL:     o.TokenURL,
		Code:         code,
		CodeVerifier: o.CodeVerifier,
	}

	header := map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
		"Accept":       "application/json",
	}

	payload := input.ToReader()

	resp, err := request.MakeRequest("POST", o.TokenURL, payload, header)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}

	var results = &TokenResponse{}

	if err := json.Unmarshal(resp, &results); err != nil {
		return nil, fmt.Errorf("failed to get access token:%w", err)
	}

	return results, nil
}
