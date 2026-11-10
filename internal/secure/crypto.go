package secure

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Sealer encrypts small secrets at rest with AES-256-GCM.
type Sealer struct {
	aead cipher.AEAD
	mac  []byte
}

// LoadOrCreateMasterKey reads the 32 byte master key from path or creates it
// with mode 0600.
func LoadOrCreateMasterKey(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err == nil {
		key, err := hex.DecodeString(strings.TrimSpace(string(b)))
		if err != nil || len(key) != 32 {
			return nil, fmt.Errorf("master key %s is corrupt", path)
		}
		return key, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, []byte(hex.EncodeToString(key)+"\n"), 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

// NewSealer creates a Sealer from a 32 byte key.
func NewSealer(key []byte) (*Sealer, error) {
	if len(key) != 32 {
		return nil, errors.New("sealer key must be 32 bytes")
	}
	encKey := hkdf(key, "ohg-seal-v1")
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Sealer{aead: aead, mac: hkdf(key, "ohg-mac-v1")}, nil
}

func hkdf(key []byte, info string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(info))
	return m.Sum(nil)
}

// Seal encrypts plaintext. The nonce is prepended.
func (s *Sealer) Seal(plaintext []byte) []byte {
	if len(plaintext) == 0 {
		return nil
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}
	return s.aead.Seal(nonce, nonce, plaintext, nil)
}

// Open decrypts data produced by Seal.
func (s *Sealer) Open(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, nil
	}
	ns := s.aead.NonceSize()
	if len(data) < ns {
		return nil, errors.New("ciphertext too short")
	}
	return s.aead.Open(nil, data[:ns], data[ns:], nil)
}

// SealString is a convenience wrapper around Seal.
func (s *Sealer) SealString(v string) []byte { return s.Seal([]byte(v)) }

// OpenString is a convenience wrapper around Open.
func (s *Sealer) OpenString(data []byte) (string, error) {
	b, err := s.Open(data)
	return string(b), err
}

// MAC returns a keyed HMAC-SHA256 of v (hex), used for non-reversible
// lookups such as cached basic-auth credentials.
func (s *Sealer) MAC(v string) string {
	m := hmac.New(sha256.New, s.mac)
	m.Write([]byte(v))
	return hex.EncodeToString(m.Sum(nil))
}

// RandomToken returns n random bytes encoded as URL-safe base64.
func RandomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// RandomCode returns a human friendly random code like "abcd-efgh-ijkl".
func RandomCode(groups int) string {
	const alphabet = "abcdefghjkmnpqrstuvwxyz23456789"
	b := make([]byte, groups*4)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	var sb strings.Builder
	for i, c := range b {
		if i > 0 && i%4 == 0 {
			sb.WriteByte('-')
		}
		sb.WriteByte(alphabet[int(c)%len(alphabet)])
	}
	return sb.String()
}

// HashToken returns the hex SHA-256 of a token (used for session IDs and
// one-time codes, which have enough entropy to not need a slow hash).
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// ConstantTimeEqual compares two strings in constant time.
func ConstantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// NewTOTPSecret returns a new random base32 TOTP secret (160 bit).
func NewTOTPSecret() string {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
}
