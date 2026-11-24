package sample

import (
	"net/http"
	"strings"
)

func DeleteAdmin(r *http.Request) bool {
	return strings.Contains(r.RemoteAddr, "127.0.0.1")
}
