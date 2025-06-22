package googleoauth

func NewOAuthClient(client OAuth2Config) *OAuth2Config {
	return &OAuth2Config{
		ClientID:     client.ClientID,
		ClientSecret: client.ClientSecret,
		CallbackURL:  client.CallbackURL,
		OAuthURL:     client.OAuthURL,
		GrantType:    client.GrantType,
		State:        client.State,
		TokenURL:     client.TokenURL,
		CodeVerifier: client.CodeVerifier,
		Code:         client.Code,
		AccessType:   client.AccessType,
	}
}
