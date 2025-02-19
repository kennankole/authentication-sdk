package firebaseauthsdk

import (
	"context"
	"fmt"

	"firebase.google.com/go/v4"
	"firebase.google.com/go/v4/auth"
	"google.golang.org/api/option"
)

type FirebaseAuthSDK struct {
	AuthClient *auth.Client
}

// Returns a Firebase Auth client
func NewFirebaseAuthSDK(ctx context.Context, credentialsFile string) (*FirebaseAuthSDK, error) {
	opt := option.WithCredentialsFile(credentialsFile)

	app, err := firebase.NewApp(ctx, nil, opt)
	if err != nil {
		return nil, fmt.Errorf("an error occurred duirng firebase app initialization %w", err)
	}

	client, err := app.Auth(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize firebase auth client: %w", err)
	}

	return &FirebaseAuthSDK{
		AuthClient: client,
	}, nil
}
