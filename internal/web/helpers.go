package web

import (
	"html/template"
	"net/http"
	"strings"

	"github.com/testbild-media/openHeadscaleGUI/internal/secure"
)

func verifyCurrent(r *http.Request, hash, pw string) (bool, error) {
	if len(pw) > 256 {
		return false, nil
	}
	return secure.VerifyPassword(r.Context(), hash, pw)
}

// qrURL marks a generated PNG data URI as safe for an img src attribute.
func qrURL(dataURI string) template.URL {
	if !strings.HasPrefix(dataURI, "data:image/png;base64,") {
		return ""
	}
	return template.URL(dataURI)
}
