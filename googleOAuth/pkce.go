package googleoauth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
)

// GenerateCodeVerifier: generates the code verifier for PKCE
func (o *OAuth2Config) GenerateCodeVerifier() (string, error) {
	code := make([]byte, 32)

	_, err := rand.Read(code)
	if err != nil {
		return "", fmt.Errorf("unable to generate code verifier: %w", err)
	}

	verifier := strings.TrimRight(base64.URLEncoding.EncodeToString(code), "=")

	return verifier, nil
}

// CodeChallenge: hashes the code verifier
func GenerateCodeChallenge(codeverifier string) string {
	shaBytes := sha256.Sum256([]byte(codeverifier))
	return strings.TrimRight(base64.URLEncoding.EncodeToString(shaBytes[:]), "=")
}
