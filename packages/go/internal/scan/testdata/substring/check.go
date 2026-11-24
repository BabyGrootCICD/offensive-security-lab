package sample

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
)

func Check(raw string) (*http.Response, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if !strings.Contains(parsed.Host, "trusted.example") {
		return nil, errors.New("host not allowed")
	}
	return http.Get(parsed.String())
}
