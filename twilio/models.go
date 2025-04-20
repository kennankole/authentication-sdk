package twilio

import (
	"github.com/twilio/twilio-go"
)

type TwillioClient struct {
	Client          *twilio.RestClient
	VerifyServiceID string
}
