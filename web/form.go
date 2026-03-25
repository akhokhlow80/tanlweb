package web

import (
	"net/url"
	"strings"
)

func FormScalar(form url.Values, field string) string {
	vals := form[field]
	if len(vals) == 0 {
		return ""
	}
	return vals[len(vals)-1]
}

func FormTrimmedScalar(form url.Values, field string) string {
	return strings.TrimSpace(FormScalar(form, field))
}
