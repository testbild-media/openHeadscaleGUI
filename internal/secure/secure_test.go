package secure

import (
	"context"
	"testing"
	"time"
)

func TestPasswordHashVerify(t *testing.T) {
	ctx := context.Background()
	h, err := HashPassword(ctx, "Richtig-Langes-Passwort-1")
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := VerifyPassword(ctx, h, "Richtig-Langes-Passwort-1"); err != nil || !ok {
		t.Fatalf("expected match, got %v %v", ok, err)
	}
	if ok, _ := VerifyPassword(ctx, h, "falsch"); ok {
		t.Fatal("wrong password accepted")
	}
	if ok, _ := VerifyPassword(ctx, "", "irgendwas"); ok {
		t.Fatal("empty hash must never verify")
	}
}

func TestPasswordPolicy(t *testing.T) {
	cases := map[string]bool{
		"kurz":                              false,
		"aaaaaaaaaaaaaaaa":                  false,
		"Lokal-Test-Kennwort-2026":          true,
		"admin-Passwort-123":                false, // contains username
		"eine lange passphrase ohne zahlen": true,
	}
	for pw, want := range cases {
		err := CheckPasswordPolicy(pw, "admin")
		if (err == nil) != want {
			t.Errorf("%q: got err=%v, want ok=%v", pw, err, want)
		}
	}
}

func TestTOTPReplay(t *testing.T) {
	secret := NewTOTPSecret()
	now := time.Unix(1_800_000_000, 0)
	code, err := totpCode(secret, now.Unix()/30)
	if err != nil {
		t.Fatal(err)
	}
	step, ok := VerifyTOTP(secret, code, 0, now)
	if !ok {
		t.Fatal("valid code rejected")
	}
	if _, ok := VerifyTOTP(secret, code, step, now); ok {
		t.Fatal("replayed code accepted")
	}
	if _, ok := VerifyTOTP(secret, "000000", 0, now); ok && code != "000000" {
		t.Fatal("wrong code accepted")
	}
}

func TestSealer(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	s, err := NewSealer(key)
	if err != nil {
		t.Fatal(err)
	}
	ct := s.SealString("geheim")
	pt, err := s.OpenString(ct)
	if err != nil || pt != "geheim" {
		t.Fatalf("roundtrip failed: %q %v", pt, err)
	}
	ct[len(ct)-1] ^= 1
	if _, err := s.Open(ct); err == nil {
		t.Fatal("tampered ciphertext accepted")
	}
}
