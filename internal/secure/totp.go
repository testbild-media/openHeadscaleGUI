package secure

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"image/png"
	"net/url"
	"strings"
	"time"

	"rsc.io/qr"
)

const totpPeriod = 30

// totpCode computes the RFC 6238 code (SHA1, 6 digits) for a time step.
func totpCode(secret string, step int64) (string, error) {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimRight(secret, "=")))
	if err != nil {
		return "", err
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step))
	m := hmac.New(sha1.New, key)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", v%1000000), nil
}

// VerifyTOTP checks code against the secret allowing one step of clock skew.
// lastStep is the last successfully used step; codes for steps <= lastStep
// are rejected to prevent replay. It returns the matched step.
func VerifyTOTP(secret, code string, lastStep int64, now time.Time) (int64, bool) {
	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	if len(code) != 6 {
		return 0, false
	}
	cur := now.Unix() / totpPeriod
	matched := int64(-1)
	for _, s := range []int64{cur - 1, cur, cur + 1} {
		want, err := totpCode(secret, s)
		if err != nil {
			return 0, false
		}
		if ConstantTimeEqual(want, code) {
			matched = s
		}
	}
	if matched < 0 || matched <= lastStep {
		return 0, false
	}
	return matched, true
}

// TOTPURI returns the otpauth:// URI for authenticator apps.
func TOTPURI(issuer, account, secret string) string {
	v := url.Values{}
	v.Set("secret", secret)
	v.Set("issuer", issuer)
	v.Set("algorithm", "SHA1")
	v.Set("digits", "6")
	v.Set("period", "30")
	return "otpauth://totp/" + url.PathEscape(issuer+":"+account) + "?" + v.Encode()
}

// QRDataURI renders text as a PNG QR code data URI.
func QRDataURI(text string) (string, error) {
	code, err := qr.Encode(text, qr.M)
	if err != nil {
		return "", err
	}
	code.Scale = 6
	var buf bytes.Buffer
	if err := png.Encode(&buf, code.Image()); err != nil {
		return "", err
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}
