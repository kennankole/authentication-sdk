package firebaseauthsdk

import (
	"context"
	"fmt"
	"net/http"

	"golang.org/x/oauth2"
	"google.golang.org/api/idtoken"
)

type OAuth2Config struct {
	Config           *oauth2.Config
	Client           *http.Client
	OauthStateString string //This should be a secure random string for the OAuth2 state parameter to prevent CSRF attacks.
}

// NewOAuthClient creats a new http client using the provided token source
func (o *OAuth2Config) NewOAuthClient(ctx context.Context, src oauth2.TokenSource) *http.Client {
	return oauth2.NewClient(ctx, src)
}

// AuthCodedURL returns the URL for the consent screen
func (o *OAuth2Config) AuthCodedURL() string {
	return o.Config.AuthCodeURL(o.OauthStateString)
}

// Exchange converts an authorization code into a token
func (o *OAuth2Config) Exchange(ctx context.Context, code string) (*oauth2.Token, error) {
	token, err := o.Config.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("could not convert code to token: %w", err)
	}
	return token, nil
}

// ValidateState validates the OAuth2 state parameter to protect against CSRF
func (o *OAuth2Config) ValidateState(state string) error {
	if o.OauthStateString != state {
		return fmt.Errorf("invalid OAuth2 state exptected: %s got %s", o.OauthStateString, state)
	}
	return nil
}

// ValidateTokenID validates the given token ID
func (o *OAuth2Config) ValidateIDToken(ctx context.Context, tokenID string) (*idtoken.Payload, error) {
	payload, err := idtoken.Validate(ctx, tokenID, o.Config.ClientID)
	if err != nil {
		return nil, fmt.Errorf("unable to validate the token ID: %w", err)
	}
	return payload, nil
}
