package request

import (
	"fmt"
	"io"
	"net/http"
	"time"
)

var client = http.Client{
	Timeout: 10 * time.Second,
}

func MakeRequest(method, url string, body io.Reader, headers map[string]string) ([]byte, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	if len(headers) > 0 {
		for key, value := range headers {
			req.Header.Set(key, value)
		}
	}

	response, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to connect: %w", err)
	}


	defer response.Body.Close()
	if response.StatusCode >= 400 {
		return nil, fmt.Errorf("request failed with status code: %v", response.Status)
	}

	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body:%w", err)
	}
	return responseBody, nil
}
