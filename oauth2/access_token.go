package fosite

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

func (o *OAuth2Config) NewAccessToken(ctx context.Context, user *VerifiedPhoneNumber) (map[string]any, error) {
	if user == nil {
		return nil, fmt.Errorf("user is empty")
	}

	if o.CodeVerifier == "" {
		_, err := o.GenerateCodeVerifier()
		if err != nil {
			return nil, err
		}
	}

	data := url.Values{}
	data.Set("grant_type", "authorization_code refresh_token")
	data.Set("username", user.PhoneNumber)
	data.Set("client_id", o.ClientID)
	data.Set("scope", "openid profile email")
	data.Set("code_verifier", o.CodeVerifier)
	data.Set("redirect_uri", o.CallbackURL)

	httpRequest, err := http.NewRequest("POST", o.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("an error occurred: %w", err)
	}

	httpRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}

	resp, err := client.Do(httpRequest)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	var tokens map[string]interface{}

	err = json.NewDecoder(resp.Body).Decode(&tokens)
	if err != nil {
		return nil, err
	}

	return tokens, nil
}
