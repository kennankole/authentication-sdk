package fosite

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/kennankole/authentication-sdk/request"
)

func (o *OAuth2Config) RefreshToken(ctx context.Context, input *RefreshTokenPayload) (*TokenResponse, error) {

	header := map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
	}

	payload := input.ToReader()

	resp, err := request.MakeRequest("POST", o.TokenURL, payload, header)
	if err != nil {
		return nil, fmt.Errorf("an error occurred: %w", err)
	}

	var results TokenResponse

	if err := json.Unmarshal(resp, &results); err != nil {
		return nil, fmt.Errorf("failed to request a new token: %w", err)
	}
	
	return &results, nil
	
} 

