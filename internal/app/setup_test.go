package app

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/testbild-media/openHeadscaleGUI/internal/config"
	"github.com/testbild-media/openHeadscaleGUI/internal/store"
)

func TestSetupTokenStable(t *testing.T) {
	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, "ohg.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	a := &App{DB: db, Cfg: &config.Config{DataDir: dir}}
	ctx := context.Background()

	t1, err := a.SetupToken(ctx, false)
	if err != nil || !a.CheckSetupToken(ctx, t1) {
		t.Fatalf("first token invalid: %q %v", t1, err)
	}
	// a restart (or "ohg setup-token") keeps the code
	if t2, _ := a.SetupToken(ctx, false); t2 != t1 {
		t.Fatalf("token changed on restart: %q -> %q", t1, t2)
	}
	// renew replaces it
	t3, _ := a.SetupToken(ctx, true)
	if t3 == t1 || a.CheckSetupToken(ctx, t1) || !a.CheckSetupToken(ctx, t3) {
		t.Fatal("renew did not replace the token")
	}
	// a stale file (e.g. hash cleared) is not reused
	_ = db.DeleteSetting(ctx, SetSetupTokenHash)
	if t4, _ := a.SetupToken(ctx, false); t4 == t3 || !a.CheckSetupToken(ctx, t4) {
		t.Fatal("stale token file was reused")
	}
	a.ClearSetupToken(ctx)
	if _, err := os.Stat(filepath.Join(dir, "setup-token")); !os.IsNotExist(err) || a.CheckSetupToken(ctx, t1) {
		t.Fatal("token not cleared")
	}
}
