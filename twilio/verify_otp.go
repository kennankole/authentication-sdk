package twilio

import (
	"context"
	"fmt"

	openapi "github.com/twilio/twilio-go/rest/verify/v2"
)

const (
	SMSChannel = "sms"
)

// CheckOTP verifies the OTP
func (t *TwillioClient) CheckOTP(ctx context.Context, phoneNumber, code string) (*openapi.VerifyV2VerificationCheck, error) {
	params := &openapi.CreateVerificationCheckParams{}
	params.SetTo(phoneNumber)
	params.SetCode(code)

	resp, err := t.Client.VerifyV2.CreateVerificationCheck(t.VerifyServiceID, params)
	if err != nil {
		return nil, fmt.Errorf("could not verify the OTP %w", err)
	}

	return resp, nil
}
