package firebaseauthsdk

import (
	"fmt"

	"github.com/twilio/twilio-go"
	openapi "github.com/twilio/twilio-go/rest/verify/v2"
)

const (
	SMSChannel = "sms"
	Approved = "approved"
)

type TwillioClient struct {
	Client          *twilio.RestClient
	VerifyServiceID string
}

func NewTwillioClient(configs *twilio.ClientParams, verifyServiceID string) *TwillioClient {
	client := twilio.NewRestClientWithParams(*configs)
	return &TwillioClient{
		Client:          client,
		VerifyServiceID: verifyServiceID,
	}
}

// SendOTP sends an OTP to a given phone number
func (t *TwillioClient) SendOTP(phoneNumber string) (string, error) {
	params := &openapi.CreateVerificationCheckParams{}
	params.SetTo(phoneNumber)
	params.SetCode(SMSChannel)

	resp, err := t.Client.VerifyV2.CreateVerificationCheck(t.VerifyServiceID, params)
	if err != nil {
		return "", fmt.Errorf("failed to send OTP %w", err)
	}
	return *resp.Sid, nil
}

// CheckOTP verifies the OTP
func (t *TwillioClient) CheckOTP(phoneNumber string) (string, error) {
	params := &openapi.CreateVerificationCheckParams{}
	params.SetTo(phoneNumber)
	params.SetCode(SMSChannel)

	resp, err := t.Client.VerifyV2.CreateVerificationCheck(t.VerifyServiceID, params)
	if err != nil {
		return "", fmt.Errorf("could not verify the OTP %s", err)
	}

	if *resp.Status == Approved {
		return "Correct", nil
	} else {
		return "Incorrect", nil
	}
}