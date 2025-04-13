package fosite

import (
	"context"
	"fmt"

	"golang.org/x/oauth2"
)

type OAuth2Cfg struct {
	Client *oauth2.Config
}

func NewOAuthClient(client *oauth2.Config) *OAuth2Cfg {
	return &OAuth2Cfg{Client: client}
}

func (o *OAuth2Cfg) CodeVerifier() string {
	return oauth2.GenerateVerifier()
}

func (o *OAuth2Cfg) AuthURL(ctx context.Context, state string) (string, error) {
	if state == "" {
		return "", fmt.Errorf("missing state")
	}
	client := NewOAuthClient(o.Client)
	url := client.Client.AuthCodeURL(state)
	return url, nil
}