package sample

import "net/http"

func Check() (*http.Response, error) {
	return http.Get("https://inventory.internal/stock")
}
