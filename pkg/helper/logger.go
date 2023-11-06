package helper

import (
	"fmt"
	"log/slog"
	"net/http"
)

func HttpServerLogger(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		msg := fmt.Sprintf("%s %s", r.Method, r.URL)
		slog.Info(msg, "method", r.Method, "url", r.URL, "remote_addr", r.RemoteAddr)
		h.ServeHTTP(w, r)
	})
}
