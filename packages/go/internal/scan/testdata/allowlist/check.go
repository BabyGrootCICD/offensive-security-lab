package sample

import (
	"errors"
	"net/http"
	"net/url"
)

func Check(raw string) (*http.Response, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if parsed.Scheme != "https" || parsed.Host != "inventory.internal" {
		return nil, errors.New("destination not allowed")
	}
	return http.Get(parsed.String())
}
