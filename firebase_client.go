package firebaseauthsdk

import (
	"context"
	"fmt"

	firebase "firebase.google.com/go/v4"
	"firebase.google.com/go/v4/auth"
	"google.golang.org/api/option"
)

type FirebaseAuthClient struct {
	AuthClient *auth.Client
}

func NewFirebaseAuthClient(ctx context.Context, credentials string) (*FirebaseAuthClient, error) {
	opt := option.WithCredentialsFile(credentials)
	app, err := firebase.NewApp(ctx, nil, opt)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Firebase app: %w", err)
	}

	authClient, err := app.Auth(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Firebase auth client: %w", err)
	}
	return &FirebaseAuthClient{
		AuthClient: authClient,
	}, nil
}

// CreateUser creates a new user given a phone number
func (f *FirebaseAuthClient) CreateUser(ctx context.Context, user *auth.UserToCreate) (*auth.UserRecord, error) {
	newUser, err := f.AuthClient.CreateUser(ctx, user)
	if err != nil {
		return nil, fmt.Errorf("could not create user: %w", err)
	}
	return newUser, nil
}

