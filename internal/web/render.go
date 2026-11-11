package web

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"math"
	"net/http"
	"path"
	"reflect"
	"strings"
	"time"

	"github.com/testbild-media/openHeadscaleGUI/internal/app"
	"github.com/testbild-media/openHeadscaleGUI/internal/store"
)

type templates struct {
	pages map[string]*template.Template
}

var funcs = template.FuncMap{
	"bytes":     humanBytes,
	"rate":      humanRate,
	"ago":       ago,
	"ts":        formatUnix,
	"tm":        formatTime,
	"tmp":       formatTimePtr,
	"spark":     sparkline,
	"ms":        func(v float64) string { return fmt.Sprintf("%.0f ms", v) },
	"pct":       func(v float64) string { return fmt.Sprintf("%.0f %%", v) },
	"join":      strings.Join,
	"upper":     strings.ToUpper,
	"lower":     strings.ToLower,
	"hasPrefix": strings.HasPrefix,
	"contains": func(list []string, v string) bool {
		for _, x := range list {
			if x == v {
				return true
			}
		}
		return false
	},
	"isExit": func(r string) bool { return r == "0.0.0.0/0" || r == "::/0" },
	"short": func(s string, n int) string {
		if len(s) <= n {
			return s
		}
		return s[:n] + "…"
	},
	"add":  func(a, b int) int { return a + b },
	"i64":  func(v any) int64 { return toInt64(v) },
	"dict": dict,
	"json": func(v any) string { b, _ := json.MarshalIndent(v, "", "  "); return string(b) },
	"now":  time.Now,
	"stateClass": func(s string) string {
		switch s {
		case "running", "online", "applied", "approved", "ok":
			return "ok"
		case "starting", "registered", "waiting", "pending":
			return "warn"
		case "crashed", "error", "rejected":
			return "bad"
		}
		return "muted"
	},
	"stateLabel": func(s string) string {
		switch s {
		case "running":
			return "läuft"
		case "starting":
			return "startet"
		case "stopped":
			return "gestoppt"
		case "crashed":
			return "abgestürzt"
		case "error":
			return "Fehler"
		case "disabled":
			return "deaktiviert"
		case "waiting":
			return "wartet auf Registrierung"
		case "registered":
			return "registriert"
		case "applied":
			return "aktiv"
		case "pending":
			return "offen"
		case "approved":
			return "freigegeben"
		case "rejected":
			return "abgelehnt"
		case "expired":
			return "abgelaufen"
		}
		return s
	},
}

// toInt64 converts any integer or float value – including named types such
// as headscale.U64 – to int64; everything else yields 0.
func toInt64(v any) int64 {
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return rv.Int()
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return int64(rv.Uint())
	case reflect.Float32, reflect.Float64:
		return int64(rv.Float())
	}
	return 0
}

func dict(kv ...any) map[string]any {
	m := map[string]any{}
	for i := 0; i+1 < len(kv); i += 2 {
		if k, ok := kv[i].(string); ok {
			m[k] = kv[i+1]
		}
	}
	return m
}

// assetVersions maps static file names to a short content hash used for
// cache busting (static files are cached by browsers).
var assetVersions = map[string]string{}

func init() {
	funcs["asset"] = func(name string) string {
		if v := assetVersions[name]; v != "" {
			return "/static/" + name + "?v=" + v
		}
		return "/static/" + name
	}
}

func loadTemplates() (*templates, error) {
	if entries, err := fs.ReadDir(assets, "static"); err == nil {
		for _, e := range entries {
			if b, err := fs.ReadFile(assets, "static/"+e.Name()); err == nil {
				sum := sha256.Sum256(b)
				assetVersions[e.Name()] = hex.EncodeToString(sum[:])[:10]
			}
		}
	}
	t := &templates{pages: map[string]*template.Template{}}
	files, err := fs.Glob(assets, "templates/*.html")
	if err != nil {
		return nil, err
	}
	for _, f := range files {
		name := strings.TrimSuffix(path.Base(f), ".html")
		if name == "layout" || name == "partials" {
			continue
		}
		tpl, err := template.New(name).Funcs(funcs).ParseFS(assets, "templates/layout.html", "templates/partials.html", f)
		if err != nil {
			return nil, fmt.Errorf("parsing %s: %w", f, err)
		}
		t.pages[name] = tpl
	}
	return t, nil
}

type flash struct {
	Kind string `json:"k"`
	Msg  string `json:"m"`
}

// page is the data passed to every template.
type page struct {
	Title       string
	Bare        bool // auth pages without navigation
	Nav         string
	Tab         string
	User        *store.User
	CSRF        string
	Flash       *flash
	Inst        *store.Instance
	InstState   string
	PendingOpen int
	Version     string
	AdminDomain string
	D           map[string]any
}

func (s *Server) setFlash(w http.ResponseWriter, kind, msg string) {
	b, _ := json.Marshal(flash{Kind: kind, Msg: msg})
	s.setCookie(w, flashCookie, base64.RawURLEncoding.EncodeToString(b), 60)
}

func (s *Server) popFlash(w http.ResponseWriter, r *http.Request) *flash {
	c, err := r.Cookie(s.cookieName(flashCookie))
	if err != nil || c.Value == "" {
		return nil
	}
	s.setCookie(w, flashCookie, "", -1)
	b, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil {
		return nil
	}
	var f flash
	if json.Unmarshal(b, &f) != nil || f.Msg == "" {
		return nil
	}
	if len(f.Msg) > 500 {
		f.Msg = f.Msg[:500]
	}
	return &f
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, rc *reqCtx, status int, name string, p page) {
	tpl := s.tpl.pages[name]
	if tpl == nil {
		http.Error(w, "template not found", http.StatusInternalServerError)
		return
	}
	p.User, p.CSRF, p.Version, p.AdminDomain = rc.User, rc.CSRF, app.Version, s.app.Cfg.AdminDomain
	if p.Flash == nil {
		p.Flash = s.popFlash(w, r)
	}
	if rc.Inst != nil {
		p.Inst = rc.Inst
		st := string(s.app.HS.Status(rc.Inst.ID).State)
		if !rc.Inst.Enabled {
			st = "disabled"
		}
		p.InstState = st
		if counts, err := s.app.DB.CountOpenPending(r.Context()); err == nil {
			p.PendingOpen = counts[rc.Inst.ID]
		}
	}
	if p.D == nil {
		p.D = map[string]any{}
	}
	var buf bytes.Buffer
	if err := tpl.ExecuteTemplate(&buf, "layout", p); err != nil {
		s.log.Error("template error", "template", name, "err", err)
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	w.Write(buf.Bytes())
}

func (s *Server) redirect(w http.ResponseWriter, r *http.Request, to string) {
	http.Redirect(w, r, to, http.StatusSeeOther)
}

// done redirects with a success flash.
func (s *Server) done(w http.ResponseWriter, r *http.Request, to, msg string) {
	if msg != "" {
		s.setFlash(w, "ok", msg)
	}
	s.redirect(w, r, to)
}

// fail redirects with an error flash and logs unexpected errors.
func (s *Server) fail(w http.ResponseWriter, r *http.Request, to string, err error) {
	if !app.IsUserError(err) {
		s.log.Error("request failed", "path", r.URL.Path, "err", err)
	}
	s.setFlash(w, "err", userMessage(err))
	s.redirect(w, r, to)
}

func (s *Server) notFound(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	s.render(w, r, rc, http.StatusNotFound, "error", page{Title: "Nicht gefunden", D: map[string]any{
		"Code": 404, "Msg": "Die Seite existiert nicht oder du hast keinen Zugriff darauf.",
	}})
}

// ---- formatting helpers ----

func humanBytes(v any) string {
	f := float64(toInt64(v))
	if fv, ok := v.(float64); ok {
		f = fv
	}
	units := []string{"B", "KB", "MB", "GB", "TB", "PB"}
	i := 0
	for f >= 1024 && i < len(units)-1 {
		f /= 1024
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%.0f %s", f, units[i])
	}
	return fmt.Sprintf("%.1f %s", f, units[i])
}

func humanRate(v float64) string {
	if v < 1 {
		return "0 B/s"
	}
	return humanBytes(v) + "/s"
}

func ago(v any) string {
	var t time.Time
	switch x := v.(type) {
	case time.Time:
		t = x
	case *time.Time:
		if x == nil {
			return "–"
		}
		t = *x
	case int64:
		if x == 0 {
			return "–"
		}
		t = time.Unix(x, 0)
	default:
		return "–"
	}
	if t.IsZero() || t.Year() < 2000 {
		return "–"
	}
	d := time.Since(t)
	future := d < 0
	if future {
		d = -d
	}
	var s string
	switch {
	case d < time.Minute:
		s = fmt.Sprintf("%d s", int(d.Seconds()))
	case d < time.Hour:
		s = fmt.Sprintf("%d min", int(d.Minutes()))
	case d < 48*time.Hour:
		s = fmt.Sprintf("%d h", int(d.Hours()))
	default:
		s = fmt.Sprintf("%d Tagen", int(d.Hours()/24))
	}
	if future {
		return "in " + s
	}
	return "vor " + s
}

func formatUnix(v int64) string {
	if v == 0 {
		return "–"
	}
	return time.Unix(v, 0).Local().Format("02.01.2006 15:04:05")
}

func formatTime(t time.Time) string {
	if t.IsZero() || t.Year() < 2000 {
		return "–"
	}
	return t.Local().Format("02.01.2006 15:04")
}

func formatTimePtr(t *time.Time) string {
	if t == nil {
		return "–"
	}
	return formatTime(*t)
}

// sparkline renders a small inline SVG chart. Only numbers end up in the
// markup, so returning template.HTML is safe.
func sparkline(vals []float64, class string) template.HTML {
	const w, h = 240.0, 48.0
	if len(vals) < 2 {
		return template.HTML(`<svg class="spark ` + template.HTMLEscapeString(class) + `" viewBox="0 0 240 48" preserveAspectRatio="none" aria-hidden="true"></svg>`)
	}
	maxV := 0.0
	for _, v := range vals {
		if !math.IsNaN(v) && v > maxV {
			maxV = v
		}
	}
	if maxV <= 0 {
		maxV = 1
	}
	step := w / float64(len(vals)-1)
	var b strings.Builder
	fmt.Fprintf(&b, `<svg class="spark %s" viewBox="0 0 240 48" preserveAspectRatio="none" aria-hidden="true">`, template.HTMLEscapeString(class))
	var seg []string
	flush := func() {
		if len(seg) > 1 {
			fmt.Fprintf(&b, `<polyline points="%s"/>`, strings.Join(seg, " "))
		} else if len(seg) == 1 {
			var x, y float64
			fmt.Sscanf(seg[0], "%f,%f", &x, &y)
			fmt.Fprintf(&b, `<circle cx="%.1f" cy="%.1f" r="1.5"/>`, x, y)
		}
		seg = seg[:0]
	}
	for i, v := range vals {
		if math.IsNaN(v) {
			flush()
			fmt.Fprintf(&b, `<line class="gap" x1="%.1f" y1="0" x2="%.1f" y2="%.0f"/>`, float64(i)*step, float64(i)*step, h)
			continue
		}
		y := h - 2 - (v/maxV)*(h-4)
		seg = append(seg, fmt.Sprintf("%.1f,%.1f", float64(i)*step, y))
	}
	flush()
	b.WriteString(`</svg>`)
	return template.HTML(b.String())
}
