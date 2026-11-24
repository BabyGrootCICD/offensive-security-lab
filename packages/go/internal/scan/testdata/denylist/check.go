package sample

import (
	"errors"
	"net/http"
	"strings"
)

func Check(raw string) (*http.Response, error) {
	if strings.Contains(raw, "localhost") || strings.Contains(raw, "127.0.0.1") {
		return nil, errors.New("blocked")
	}
	return http.Get(raw)
}
