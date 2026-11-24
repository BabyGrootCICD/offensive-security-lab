package sample

import "net/http"

func Check(r *http.Request) (*http.Response, error) {
	raw := r.FormValue("stockApi")
	return http.Get(raw)
}

func CheckSprintf(id string) (*http.Response, error) {
	return http.Get("https://" + id + "/stock")
}
