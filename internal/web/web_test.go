package web

import (
	"math"
	"strings"
	"testing"
)

func TestTemplatesParse(t *testing.T) {
	tpl, err := loadTemplates()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"login", "dashboard", "instance", "node", "pending", "clients", "forwards",
		"monitor", "derp", "users", "settings", "audit", "profile", "twofa", "policy", "logs"} {
		if tpl.pages[name] == nil {
			t.Errorf("template %s missing", name)
		}
	}
	if !strings.Contains(funcs["asset"].(func(string) string)("app.css"), "?v=") {
		t.Error("static assets are not versioned")
	}
}

func TestSparklineOnlyNumbers(t *testing.T) {
	out := string(sparkline([]float64{1, 2, math.NaN(), 4}, `x" onload="alert(1)`))
	if strings.Contains(out, `onload="`) {
		t.Fatal("class attribute not escaped")
	}
	if !strings.Contains(out, "<polyline") || !strings.Contains(out, `class="gap"`) {
		t.Fatalf("unexpected svg: %s", out)
	}
}

func TestSafeNext(t *testing.T) {
	for in, want := range map[string]string{
		"/i/1":              "/i/1",
		"//evil.example":    "/",
		"https://evil.test": "/",
		"/\\evil":           "/",
		"":                  "/",
	} {
		if got := safeNext(in); got != want {
			t.Errorf("safeNext(%q) = %q, want %q", in, got, want)
		}
	}
}
