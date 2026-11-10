// Package secure contains the cryptographic building blocks of ohg:
// password hashing (Argon2id), secret sealing (AES-256-GCM), TOTP and
// random tokens.
package secure

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters (OWASP recommendation: m=64MiB, t=3, p=2 is
// comfortably above the minimum of m=19MiB, t=2, p=1).
const (
	argonTime    = 3
	argonMemory  = 64 * 1024
	argonThreads = 2
	argonKeyLen  = 32
	argonSaltLen = 16
)

// hashSlots limits the number of concurrent Argon2id computations so that a
// flood of login requests cannot exhaust the server memory.
var hashSlots = make(chan struct{}, 4)

func acquire(ctx context.Context) error {
	select {
	case hashSlots <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func release() { <-hashSlots }

// HashPassword returns an encoded Argon2id hash.
func HashPassword(ctx context.Context, password string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	if err := acquire(ctx); err != nil {
		return "", err
	}
	defer release()
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

// dummyHash is used to equalize timing when a user does not exist.
var dummyHash = sync.OnceValue(func() string {
	h, _ := HashPassword(context.Background(), "ohg-dummy-password-for-timing")
	return h
})

// VerifyPassword checks password against an encoded hash in constant time.
// An empty encoded hash triggers a dummy computation and returns false.
func VerifyPassword(ctx context.Context, encoded, password string) (bool, error) {
	if encoded == "" {
		ok, err := VerifyPassword(ctx, dummyHash(), password+"\x00invalid")
		_ = ok
		return false, err
	}
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, errors.New("unsupported hash format")
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false, errors.New("unsupported argon2 version")
	}
	var m, t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return false, errors.New("invalid argon2 parameters")
	}
	if m > 1024*1024 || t > 20 || p == 0 || p > 16 {
		return false, errors.New("argon2 parameters out of range")
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, err
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(want) == 0 || len(want) > 128 {
		return false, errors.New("invalid hash")
	}
	if err := acquire(ctx); err != nil {
		return false, err
	}
	defer release()
	got := argon2.IDKey([]byte(password), salt, t, m, p, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// commonPasswords is a tiny deny list of passwords that pass the length
// requirement but are still trivially guessable.
var commonPasswords = map[string]bool{
	"passwordpassword": true, "password1234": true, "123456789012": true,
	"qwertzuiopü": true, "qwertyuiop12": true, "adminadmin123": true,
	"administrator": true, "headscale123": true, "tailscale123": true,
	"changemechangeme": true, "letmeinletmein": true, "passwort1234": true,
}

// MinPasswordLength is the minimum accepted password length.
const MinPasswordLength = 12

// CheckPasswordPolicy validates a new password.
func CheckPasswordPolicy(password, username string) error {
	n := utf8.RuneCountInString(password)
	if n < MinPasswordLength {
		return fmt.Errorf("Das Passwort muss mindestens %d Zeichen lang sein", MinPasswordLength)
	}
	if n > 256 {
		return errors.New("Das Passwort ist zu lang (max. 256 Zeichen)")
	}
	lower := strings.ToLower(password)
	if username != "" && strings.Contains(lower, strings.ToLower(username)) {
		return errors.New("Das Passwort darf den Benutzernamen nicht enthalten")
	}
	if commonPasswords[lower] {
		return errors.New("Dieses Passwort ist zu verbreitet")
	}
	var classes int
	var hasLower, hasUpper, hasDigit, hasOther bool
	distinct := map[rune]bool{}
	for _, r := range password {
		distinct[r] = true
		switch {
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsDigit(r):
			hasDigit = true
		default:
			hasOther = true
		}
	}
	for _, b := range []bool{hasLower, hasUpper, hasDigit, hasOther} {
		if b {
			classes++
		}
	}
	if len(distinct) < 6 {
		return errors.New("Das Passwort enthält zu wenige unterschiedliche Zeichen")
	}
	// Long passphrases are fine with fewer classes.
	if classes < 3 && n < 20 {
		return errors.New("Bitte mindestens 3 Zeichenarten verwenden (Klein-, Großbuchstaben, Ziffern, Sonderzeichen) oder eine Passphrase ab 20 Zeichen")
	}
	return nil
}
