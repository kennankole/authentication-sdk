package domain

import "time"

// OTPResponse struct for OTPResponse
type OTPResponse struct {
	Sid              *string        `json:"sid,omitempty"`
	ServiceSid       *string        `json:"service_sid,omitempty"`
	AccountSid       *string        `json:"account_sid,omitempty"`
	To               *string        `json:"to,omitempty"`
	Channel          *string        `json:"channel,omitempty"`
	Status           *string        `json:"status,omitempty"`
	Lookup           *interface{}   `json:"lookup,omitempty"`
	SendCodeAttempts *[]interface{} `json:"send_code_attempts,omitempty"`
	DateCreated      *time.Time     `json:"date_created,omitempty"`
	DateUpdated      *time.Time     `json:"date_updated,omitempty"`
}
