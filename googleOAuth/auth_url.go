package googleoauth

import (
	"context"
	"fmt"
)

// AuthorizationURL: Redirects the user to the consent screen to obtain permission to access user details from the resource server(Google)
func (o *OAuth2Config) AuthorizationURL(ctx context.Context, oauthState, verifier string) (string, error) {
	url := fmt.Sprintf("%s/oauth2/auth?", o.OAuthURL)

	if oauthState == "" {
		return "", fmt.Errorf("state is missing")
	}

	if verifier == "" {
		return "", fmt.Errorf("verifier missing")
	}

	codeChallenge := GenerateCodeChallenge(verifier)

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
		oauthState,
		codeChallenge,
	)

	return oauthURL, nil
}
