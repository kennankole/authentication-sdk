package twilio

import (
	"context"
	"github.com/twilio/twilio-go"
)

func NewTwillioClient(ctx context.Context, configs *twilio.ClientParams, verifyServiceID string) *TwillioClient {
	client := twilio.NewRestClientWithParams(*configs)
	return &TwillioClient{
		Client:          client,
		VerifyServiceID: verifyServiceID,
	}
}


