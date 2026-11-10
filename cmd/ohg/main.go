// Command ohg is OpenHeadscaleGUI: a multi-tenant management server for
// self-hosted Tailscale networks based on headscale.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"golang.org/x/term"

	"github.com/testbild-media/openHeadscaleGUI/internal/app"
	"github.com/testbild-media/openHeadscaleGUI/internal/config"
	"github.com/testbild-media/openHeadscaleGUI/internal/headscale"
	"github.com/testbild-media/openHeadscaleGUI/internal/secure"
	"github.com/testbild-media/openHeadscaleGUI/internal/store"
	"github.com/testbild-media/openHeadscaleGUI/internal/web"
)

func usage() {
	fmt.Fprintf(os.Stderr, `OpenHeadscaleGUI (ohg) %s

Verwendung:
  ohg serve                         Server starten (Standard)
  ohg version                       Version anzeigen
  ohg check                         Konfiguration und Headscale-Binary prüfen
  ohg setup-token                   neuen Einrichtungs-Code für den ersten Superadmin erzeugen
  ohg user list                     Benutzer auflisten
  ohg user add NAME [-superadmin] [-email MAIL] [-password-stdin]
  ohg user passwd NAME [-password-stdin]
  ohg user reset-2fa NAME           Zwei-Faktor-Anmeldung zurücksetzen
  ohg user unlock NAME              Login-Sperre aufheben
  ohg headscale SLUG ARGS...        headscale-CLI für eine Instanz ausführen

Konfiguration über Umgebungsvariablen bzw. %s (OHG_ENV_FILE).
`, app.Version, config.DefaultEnvFile)
}

func main() {
	envFile := os.Getenv("OHG_ENV_FILE")
	if envFile == "" {
		envFile = config.DefaultEnvFile
	}
	if err := config.LoadEnvFile(envFile); err != nil {
		fatal("reading %s: %v", envFile, err)
	}
	// Never upload logs of the embedded tailscale nodes to Tailscale Inc.
	os.Setenv("TS_NO_LOGS_NO_SUPPORT", "true")

	args := os.Args[1:]
	cmd := "serve"
	if len(args) > 0 {
		cmd, args = args[0], args[1:]
	}
	switch cmd {
	case "serve":
		serve()
	case "version", "-v", "--version":
		fmt.Println("ohg", app.Version)
	case "check":
		check()
	case "setup-token":
		setupToken()
	case "user", "users":
		userCmd(args)
	case "headscale", "hs":
		headscaleCmd(args)
	case "help", "-h", "--help":
		usage()
	default:
		usage()
		os.Exit(2)
	}
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "ohg: "+format+"\n", args...)
	os.Exit(1)
}

func newLogger(level string) *slog.Logger {
	var l slog.Level
	switch level {
	case "debug":
		l = slog.LevelDebug
	case "warn":
		l = slog.LevelWarn
	case "error":
		l = slog.LevelError
	default:
		l = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: l}))
}

func loadConfig() *config.Config {
	cfg, err := config.Load()
	if err != nil {
		fatal("%v", err)
	}
	return cfg
}

func openApp(cfg *config.Config) *app.App {
	dropPrivileges(cfg.DataDir)
	a, err := app.New(cfg, newLogger("warn"))
	if err != nil {
		fatal("%v", err)
	}
	return a
}

func serve() {
	cfg := loadConfig()
	if err := cfg.ValidateForServe(); err != nil {
		fatal("%v", err)
	}
	refuseRootServe(cfg.DataDir)
	log := newLogger(cfg.LogLevel)
	a, err := app.New(cfg, log)
	if err != nil {
		fatal("%v", err)
	}
	w, err := web.New(a)
	if err != nil {
		fatal("loading web GUI: %v", err)
	}
	a.Web = w

	ctx := context.Background()
	if n, err := a.DB.CountUsers(ctx); err == nil && n == 0 {
		token, err := a.NewSetupToken(ctx)
		if err != nil {
			fatal("creating setup token: %v", err)
		}
		path := filepath.Join(cfg.DataDir, "setup-token")
		_ = os.WriteFile(path, []byte(token+"\n"), 0o600)
		log.Warn("================================================================")
		log.Warn("Ersteinrichtung: noch kein Benutzer vorhanden", "url", cfg.AdminURL()+"/setup")
		log.Warn("Einrichtungs-Code", "token", token)
		log.Warn("================================================================")
	} else {
		_ = os.Remove(filepath.Join(cfg.DataDir, "setup-token"))
	}

	if err := a.Start(); err != nil {
		fatal("start: %v", err)
	}
	log.Info("OpenHeadscaleGUI läuft", "version", app.Version, "admin", cfg.AdminURL())

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	s := <-sig
	log.Info("shutting down", "signal", s.String())
	sctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	a.Shutdown(sctx)
}

func check() {
	cfg := loadConfig()
	ok := true
	if err := cfg.ValidateForServe(); err != nil {
		fmt.Println("✗ Konfiguration:", err)
		ok = false
	} else {
		fmt.Println("✓ Konfiguration, Admin-URL:", cfg.AdminURL())
	}
	dropPrivileges(cfg.DataDir)
	m := headscale.NewManager(cfg.HeadscaleBin, newLogger("error"))
	if v, err := m.CheckBinary(context.Background()); err != nil {
		fmt.Println("✗ Headscale:", err)
		ok = false
	} else {
		fmt.Println("✓ Headscale", v, "unter", cfg.HeadscaleBin)
	}
	if st, err := os.Stat(cfg.DataDir); err != nil || !st.IsDir() {
		fmt.Println("✗ Datenverzeichnis fehlt:", cfg.DataDir)
		ok = false
	} else {
		fmt.Println("✓ Datenverzeichnis", cfg.DataDir)
	}
	if !ok {
		os.Exit(1)
	}
}

func setupToken() {
	a := openApp(loadConfig())
	defer a.Close()
	ctx := context.Background()
	n, err := a.DB.CountUsers(ctx)
	if err != nil {
		fatal("%v", err)
	}
	if n > 0 {
		fatal("es existieren bereits Benutzer – Ersteinrichtung ist abgeschlossen (siehe „ohg user add“)")
	}
	t, err := a.NewSetupToken(ctx)
	if err != nil {
		fatal("%v", err)
	}
	_ = os.WriteFile(filepath.Join(a.Cfg.DataDir, "setup-token"), []byte(t+"\n"), 0o600)
	fmt.Println("Einrichtungs-Code:", t)
	fmt.Println("Ersteinrichtung:  ", a.Cfg.AdminURL()+"/setup")
}

func readPassword(fromStdin bool, confirm bool) string {
	if fromStdin || !term.IsTerminal(int(os.Stdin.Fd())) {
		r := bufio.NewReader(os.Stdin)
		line, err := r.ReadString('\n')
		if err != nil && !errors.Is(err, os.ErrClosed) && line == "" {
			fatal("Passwort konnte nicht gelesen werden")
		}
		return strings.TrimRight(line, "\r\n")
	}
	fmt.Fprint(os.Stderr, "Passwort: ")
	p1, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		fatal("%v", err)
	}
	if confirm {
		fmt.Fprint(os.Stderr, "Wiederholen: ")
		p2, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			fatal("%v", err)
		}
		if string(p1) != string(p2) {
			fatal("die Passwörter stimmen nicht überein")
		}
	}
	return string(p1)
}

func userCmd(args []string) {
	if len(args) == 0 {
		usage()
		os.Exit(2)
	}
	sub, args := args[0], args[1:]
	a := openApp(loadConfig())
	defer a.Close()
	ctx := context.Background()
	cliActor := app.Actor{User: &store.User{ID: 0, Username: "cli", Role: store.RoleSuperadmin}, IP: "local-cli"}

	switch sub {
	case "list", "ls":
		users, err := a.DB.ListUsers(ctx)
		if err != nil {
			fatal("%v", err)
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tBENUTZER\tROLLE\t2FA\tSTATUS\tLETZTE ANMELDUNG")
		for _, u := range users {
			status := "aktiv"
			if u.Disabled {
				status = "deaktiviert"
			} else if u.Locked(time.Now()) {
				status = "gesperrt"
			}
			last := "-"
			if u.LastLoginAt > 0 {
				last = time.Unix(u.LastLoginAt, 0).Format("2006-01-02 15:04")
			}
			fmt.Fprintf(tw, "%d\t%s\t%s\t%v\t%s\t%s\n", u.ID, u.Username, u.Role, u.TOTPEnabled, status, last)
		}
		tw.Flush()
	case "add", "create":
		fs := flag.NewFlagSet("user add", flag.ExitOnError)
		super := fs.Bool("superadmin", false, "Superadmin-Rechte")
		email := fs.String("email", "", "E-Mail-Adresse")
		stdin := fs.Bool("password-stdin", false, "Passwort von stdin lesen")
		name, rest := splitName(args)
		fs.Parse(rest)
		if name == "" {
			fatal("Benutzername fehlt")
		}
		role := store.RoleUser
		if *super {
			role = store.RoleSuperadmin
		}
		pw := readPassword(*stdin, true)
		actor := cliActor
		if n, _ := a.DB.CountUsers(ctx); n == 0 {
			actor = app.Actor{IP: "local-cli"}
		}
		u, err := a.CreateUser(ctx, actor, app.UserRequest{Username: name, Email: *email, Password: pw, Role: role})
		if err != nil {
			fatal("%v", err)
		}
		a.ClearSetupToken(ctx)
		_ = os.Remove(filepath.Join(a.Cfg.DataDir, "setup-token"))
		fmt.Printf("Benutzer %s (%s) angelegt.\n", u.Username, u.Role)
	case "passwd", "password":
		fs := flag.NewFlagSet("user passwd", flag.ExitOnError)
		stdin := fs.Bool("password-stdin", false, "Passwort von stdin lesen")
		name, rest := splitName(args)
		fs.Parse(rest)
		u := mustUser(ctx, a, name)
		pw := readPassword(*stdin, true)
		if err := secure.CheckPasswordPolicy(pw, u.Username); err != nil {
			fatal("%v", err)
		}
		if err := a.SetUserPassword(ctx, cliActor, u, pw, false, ""); err != nil {
			fatal("%v", err)
		}
		fmt.Println("Passwort gesetzt, alle Sitzungen beendet.")
	case "reset-2fa":
		name, _ := splitName(args)
		u := mustUser(ctx, a, name)
		if err := a.ResetUser2FA(ctx, cliActor, u); err != nil {
			fatal("%v", err)
		}
		fmt.Println("Zwei-Faktor-Anmeldung zurückgesetzt.")
	case "unlock":
		name, _ := splitName(args)
		u := mustUser(ctx, a, name)
		if err := a.UnlockUser(ctx, cliActor, u); err != nil {
			fatal("%v", err)
		}
		fmt.Println("Sperre aufgehoben.")
	default:
		usage()
		os.Exit(2)
	}
}

func splitName(args []string) (string, []string) {
	var name string
	var rest []string
	for _, a := range args {
		if name == "" && !strings.HasPrefix(a, "-") {
			name = a
			continue
		}
		rest = append(rest, a)
	}
	return name, rest
}

func mustUser(ctx context.Context, a *app.App, name string) *store.User {
	if name == "" {
		fatal("Benutzername fehlt")
	}
	u, err := a.DB.GetUserByName(ctx, name)
	if err != nil {
		fatal("Benutzer %q nicht gefunden", name)
	}
	return u
}

func headscaleCmd(args []string) {
	if len(args) < 1 {
		fatal("Verwendung: ohg headscale SLUG ARGS...")
	}
	cfg := loadConfig()
	a := openApp(cfg)
	inst, err := a.DB.GetInstanceBySlug(context.Background(), args[0])
	a.Close()
	if err != nil {
		fatal("Instanz %q nicht gefunden", args[0])
	}
	dir := a.InstanceDir(inst.Slug)
	cmd := exec.Command(cfg.HeadscaleBin, append([]string{"-c", headscale.ConfigPath(dir)}, args[1:]...)...)
	cmd.Dir = dir
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			os.Exit(ee.ExitCode())
		}
		fatal("%v", err)
	}
}
