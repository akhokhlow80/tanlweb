package web

import (
	"akhokhlow80/tanlweb/reqlog"
	"net/http"
	"time"
)

type loggedResposneWriter struct {
	http.ResponseWriter
	httpStatus int
}

func (w *loggedResposneWriter) WriteHeader(code int) {
	w.httpStatus = code
	w.ResponseWriter.WriteHeader(code)
}

func LogMiddleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t1 := time.Now()
		// http.StatusOK is set by w.Write() if w.WriteHeader() was never called
		lw := loggedResposneWriter{w, http.StatusOK}
		h.ServeHTTP(&lw, r)
		elapsed := time.Since(t1)
		reqlog.Printf(r, "status %d in %d ms", lw.httpStatus, elapsed.Microseconds())
	})
}
