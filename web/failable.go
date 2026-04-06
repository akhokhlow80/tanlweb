package web

import (
	"akhokhlow80/tanlweb/reqlog"
	"net/http"
)

// FailableResponseWriter allows you to discard data that was previously written by WriteHeader()
// or Write() methods using the Fail() method.
type FailableResponseWriter struct {
	header http.Header
	bytes  []byte
	status int
}

var _ http.ResponseWriter = &FailableResponseWriter{}

// Header implements http.ResponseWriter.
func (f *FailableResponseWriter) Header() http.Header {
	return f.header
}

// WriteHeader implements http.ResponseWriter.
func (f *FailableResponseWriter) WriteHeader(statusCode int) {
	f.status = statusCode
}

// Write implements http.ResponseWriter.
func (f *FailableResponseWriter) Write(p []byte) (n int, err error) {
	f.bytes = append(f.bytes, p...)
	return len(p), nil
}

// Discard data previously written by other methods.
func (f *FailableResponseWriter) Fail() {
	// XXX: also discard headers?
	f.bytes = f.bytes[:0]
}

type FailableHandlerFunc func(w http.ResponseWriter, r *http.Request) error

func FailableHandler(
	errorHandler func(w http.ResponseWriter, r *http.Request, err error),
	reqHandler FailableHandlerFunc,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fw := FailableResponseWriter{
			bytes:  make([]byte, 0, 1024),
			status: http.StatusOK,
			header: w.Header(),
		}
		if err := reqHandler(&fw, r); err != nil {
			errorHandler(w, r, err)
			return
		}
		w.WriteHeader(fw.status)
		for len(fw.bytes) != 0 {
			n, err := w.Write(fw.bytes)
			if err != nil {
				reqlog.Printf(r, "Failed to write response: %s", err)
				return
			}
			fw.bytes = fw.bytes[n:]
		}
	}
}
