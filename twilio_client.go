package firebaseauthsdk

import (
	"context"
	"fmt"

	"github.com/kennankole/authentication-sdk/domain"
	"github.com/twilio/twilio-go"
	openapi "github.com/twilio/twilio-go/rest/verify/v2"
)

const (
	SMSChannel = "sms"
)

type TwillioClient struct {
	Client          *twilio.RestClient
	VerifyServiceID string
}

func NewTwillioClient(ctx context.Context, configs *twilio.ClientParams, verifyServiceID string) *TwillioClient {
	client := twilio.NewRestClientWithParams(*configs)
	return &TwillioClient{
		Client:          client,
		VerifyServiceID: verifyServiceID,
	}
}

// SendOTP sends an OTP to a given phone number
func (t *TwillioClient) SendOTP(ctx context.Context, phoneNumber string) (*domain.OTPResponse, error) {
	params := &openapi.CreateVerificationCheckParams{}
	params.SetTo(phoneNumber)
	params.SetCode(SMSChannel)

	resp, err := t.Client.VerifyV2.CreateVerificationCheck(t.VerifyServiceID, params)
	if err != nil {
		return nil, fmt.Errorf("failed to send OTP %w", err)
	}
	return &domain.OTPResponse{
		Sid: resp.Sid,
		ServiceSid: resp.ServiceSid,
		AccountSid: resp.AccountSid,
		Channel: resp.Channel,
		To: resp.To,
		Status: resp.Status,
		DateCreated: resp.DateCreated,
		DateUpdated: resp.DateUpdated,
	}, nil
}

// CheckOTP verifies the OTP
func (t *TwillioClient) CheckOTP(ctx context.Context, phoneNumber string) (*domain.OTPResponse, error) {
	params := &openapi.CreateVerificationCheckParams{}
	params.SetTo(phoneNumber)
	params.SetCode(SMSChannel)

	resp, err := t.Client.VerifyV2.CreateVerificationCheck(t.VerifyServiceID, params)
	if err != nil {
		return nil, fmt.Errorf("could not verify the OTP %s", err)
	}
	return &domain.OTPResponse{
		Sid: resp.Sid,
		ServiceSid: resp.ServiceSid,
		AccountSid: resp.AccountSid,
		Channel: resp.Channel,
		To: resp.To,
		Status: resp.Status,
		DateCreated: resp.DateCreated,
		DateUpdated: resp.DateUpdated,
	}, nil

}
