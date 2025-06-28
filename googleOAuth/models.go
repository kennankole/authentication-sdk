package googleoauth

import (
	"net/url"
	"strings"

	"github.com/MicahParks/keyfunc/v2"
	"github.com/golang-jwt/jwt/v5"
)

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
	AccessType   string  `json:"access_type,omitempty"`
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
	form.Set("access_token", o.AccessType)

	return strings.NewReader(form.Encode())
}

type TokenResponse struct {
	AccessToken  string `json:"access_token,omitempty"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
	TokenType    string `json:"token_type,omitempty"`
	TokenID      string `json:"id_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

type GoogleAuthService struct {
	GoogleJWKS *keyfunc.JWKS
	ClientID   string `json:"client_id,omitempty"`
}

type TokenIDClaims struct {
	jwt.RegisteredClaims
	JWTToken            jwt.Token `json:"jwt_token,omitempty"`
	Email               string    `json:"email,omitempty"`
	EmailVerified       bool      `json:"email_verified,omitempty"`
	Name                string    `json:"name,omitempty"`
	Picture             string    `json:"picture,omitempty"`
	GivenName           string    `json:"given_name,omitempty"`
	FamilyName          string    `json:"family_name,omitempty"`
	Locale              string    `json:"locale,omitempty"`
	PhoneNumber         string    `json:"phone_number,omitempty"`
	PhoneNumberVerified bool      `json:"phone_number_verified,omitempty"`
	ID                  string    `json:"sub"`
}
