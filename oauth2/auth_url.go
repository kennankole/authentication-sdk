package fosite

import (
	"fmt"
)

// AuthorizationURL: Get Authorization Code
func (o *OAuth2Config) AuthorizationURL() (string, error) {
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
			"code_challenge_method=S256",
		url,
		o.ClientID,
		o.CallbackURL,
		"openid profile email",
		o.State,
		codeChallenge,
	)
	return oauthURL, nil
}

