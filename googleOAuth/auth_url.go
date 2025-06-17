package googleoauth

import (
	"context"
	"fmt"
)

// https://developers.google.com/identity/protocols/oauth2/web-server

// AuthorizationURL: Redirects the user to the consent screen to obtain permission to access user details from the resource server(Google)
func (o *OAuth2Config) AuthorizationURL(ctx context.Context) (string, error) {
	url := fmt.Sprintf("%s/oauth2/auth?", o.OAuthURL)

	if o.State == "" {
		return "", fmt.Errorf("oauth state string is empty")
	}

	if o.CodeVerifier == "" {
		if _, err := o.GenerateCodeVerifier(); err != nil {
			return "", fmt.Errorf("failed to generate code verifier: %w", err)
		}
	}

	codeChallenge := GenerateCodeChallenge(o.CodeVerifier)

	oauthURL := fmt.Sprintf(
		"%s"+
			"client_id=%s&"+
			"redirect_uri=%s&"+
			"response_type=code&"+
			"scope=%s&"+
			"state=%s&"+
			"code_challenge=%s&"+
			"code_challenge_method=S256&"+
			"access_type=offline",
		url,
		o.ClientID,
		o.CallbackURL,
		"openid profile email phone",
		o.State,
		codeChallenge,
	)

	return oauthURL, nil
}
