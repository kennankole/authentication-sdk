package twilio

import (
	"context"
	"fmt"

	openapi "github.com/twilio/twilio-go/rest/verify/v2"
)

// SendOTP sends an OTP to a given phone number
func (t *TwillioClient) SendOTP(ctx context.Context, phoneNumber string) (*openapi.VerifyV2Verification, error) {
	params := &openapi.CreateVerificationParams{}
	params.SetTo(phoneNumber)
	params.SetChannel(SMSChannel)

	resp, err := t.Client.VerifyV2.CreateVerification(t.VerifyServiceID, params)
	if err != nil {
		return nil, fmt.Errorf("failed to send OTP %w", err)
	}

	return resp, nil
}
