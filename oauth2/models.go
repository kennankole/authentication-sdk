package fosite

import (
	"net/url"
	"strings"
	"time"
)

// FositeOAuthConfig represents Ory Fosite configuration details
type FositeOAuthConfig struct {
	PrivateKey string
	Storage    interface{}
	Config     Config
}

type Config struct {
	// AccessTokenLifespan sets how long an access token is going to be valid. Defaults to one houo.
	AccessTokenLifespan time.Duration

	// RefreshTokenLifespan sets how long a refresh token is going to be valid. Defaults to 30 days. Set to -1 for
	// refresh tokens that never expire.
	RefreshTokenLifespan time.Duration

	// GlobalSecret is the global secret used to sign and verify signatures.
	GlobalSecret []byte
}

type OAuth2Config struct {
	State        string  `json:"state,omitempty"`
	ClientID     string  `json:"client_id,omitempty"`
	ClientSecret string  `json:"client_secret,omitempty"`
	CallbackURL  string  `json:"callback_url,omitempty"`
	OAuthURL     string  `json:"oauthUrl,omitempty"`
	GrantType    string  `json:"grant_type,omitempty"`
	Code         *string `json:"code,omitempty"`
	TokenURL     string  `json:"token_url,omitempty"`
	CodeVerifier string  `json:"code_verifier,omitempty"`
}

func (o *OAuth2Config) ToReader() *strings.Reader {
	form := url.Values{}

	form.Set("client_id", o.ClientID)
	form.Set("client_secret", o.ClientSecret)
	form.Set("redirect_uri", o.CallbackURL)
	form.Set("token_url", o.TokenURL)
	form.Set("code", *o.Code)
	form.Set("grant_type", o.GrantType)
	form.Set("code_verifier", o.CodeVerifier)

	return strings.NewReader(form.Encode())
}

type TokenResponse struct {
	AccessToken  string `json:"access_token,omitempty"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
	TokenType    string `json:"token_type,omitempty"`
	TokenID      string `json:"id_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

type Client struct {
	Timeout time.Duration
}

type RefreshTokenPayload struct {
	ClientID     string
	ClientSecret string
	RefreshToken string
	GrantType    string
}

type VerifiedPhoneNumber struct {
	Sid         string `json:"sid,omitempty"`
	PhoneNumber string `string:"phone,omitempty"`
}

func (r *RefreshTokenPayload) ToReader() *strings.Reader {
	form := url.Values{}

	form.Set("client_id", r.ClientID)
	form.Set("client_secret", r.ClientSecret)
	form.Set("refresh_token", r.RefreshToken)
	form.Set("grant_type", r.GrantType)

	return strings.NewReader(form.Encode())
}
