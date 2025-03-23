package fosite

import (
	"context"
	"fmt"

	"github.com/kennankole/authentication-sdk/request"
)


// FetchUserData fetches users data from the resource owner
func (o *OAuth2Config) FetchUserData(ctx context.Context, accessToken, idpEndpoint string) ([]byte, error) {
	if accessToken == "" || idpEndpoint == "" {
		return nil, fmt.Errorf("access token or endpoint missing")
	}

	headers := map[string]string{
		"Authorization": "Bearer " + accessToken,
	}

	resp, err := request.MakeRequest("GET", idpEndpoint, nil, headers)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch user data: %w", err)
	}

	return resp, nil
}
