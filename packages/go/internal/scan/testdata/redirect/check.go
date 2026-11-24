package sample

import "net/http"

func Check(raw string) (*http.Response, error) {
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return nil
		},
	}
	return client.Get(raw)
}
