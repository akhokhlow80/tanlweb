package reqlog

import (
	"fmt"
	"log"
	"net/http"
)

func Printf(r *http.Request, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	log.Printf("%s %s from %s: %s", r.Method, r.URL, r.RemoteAddr, msg)
}
