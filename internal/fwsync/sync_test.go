package fwsync

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// fakeUFW simulates "ufw status/allow/delete".
type fakeUFW struct {
	lines []string // rule lines as "ufw status" prints them
	calls []string
}

func (f *fakeUFW) run(name string, args ...string) (string, error) {
	f.calls = append(f.calls, name+" "+strings.Join(args, " "))
	if name != "ufw" {
		return "", errors.New("not found")
	}
	switch {
	case len(args) == 1 && args[0] == "status":
		return "Status: active\n\nTo                         Action      From\n--                         ------      ----\n" +
			strings.Join(f.lines, "\n") + "\n", nil
	case len(args) == 4 && args[0] == "allow" && args[2] == "comment":
		for _, l := range f.lines {
			if strings.Fields(l)[0] == args[1] {
				return "Skipping adding existing rule\n", nil
			}
		}
		f.lines = append(f.lines, fmt.Sprintf("%-26s ALLOW       Anywhere                   # %s", args[1], args[3]))
		return "Rule added\nRule added (v6)\n", nil
	case len(args) == 3 && args[0] == "delete" && args[1] == "allow":
		var keep []string
		for _, l := range f.lines {
			if strings.Fields(l)[0] != args[2] {
				keep = append(keep, l)
			}
		}
		f.lines = keep
		return "Rule deleted\n", nil
	}
	return "", fmt.Errorf("unexpected %v", args)
}

func testOptions(t *testing.T, desired []Port, listening []string) Options {
	t.Helper()
	dir := t.TempDir()
	listen := map[string]bool{}
	for _, l := range listening {
		listen[l] = true
	}
	return Options{
		DataDir: filepath.Join(dir, "data"), StateDir: filepath.Join(dir, "state"),
		Have:        func(string) bool { return true },
		OwnerUID:    func(string) (int, error) { return 997, nil },
		ReadDesired: func(string, int) ([]Port, error) { return desired, nil },
		Listening:   func(uid int) (map[string]bool, error) { return listen, nil },
		Sleep:       func(time.Duration) {},
	}
}

func states(st *Status) string {
	var out []string
	for _, p := range st.Ports {
		out = append(out, p.Key()+"="+p.State)
	}
	return strings.Join(out, " ")
}

func TestSyncUFW(t *testing.T) {
	ufw := &fakeUFW{lines: []string{
		"22/tcp                     ALLOW       Anywhere",
		"8080/tcp                   ALLOW       Anywhere",                                 // admin rule
		"21114:21119/tcp            ALLOW       Anywhere",                                 // admin range
		"5432/tcp                   ALLOW       10.11.0.0/22",                             // admin restricted
		"Anywhere                   ALLOW       10.11.0.0/22",                             // not a port rule
		"30000/udp                  ALLOW       Anywhere                   # ohg-forward", // stale, ours
		"30000/udp (v6)             ALLOW       Anywhere (v6)              # ohg-forward",
	}}
	desired := []Port{
		{Port: 25565, Proto: "tcp"}, {Port: 25565, Proto: "udp"}, // new forward
		{Port: 8080, Proto: "tcp"},  // already open by the admin
		{Port: 21115, Proto: "tcp"}, // inside an admin range
		{Port: 5432, Proto: "tcp"},  // admin restricts it
		{Port: 22, Proto: "tcp"},    // never
		{Port: 26000, Proto: "tcp"}, // ohg does not listen (port busy)
		{Port: 27000, Proto: "sctp"},
	}
	o := testOptions(t, desired, []string{"25565/tcp", "25565/udp", "8080/tcp", "21115/tcp", "5432/tcp", "22/tcp"})
	o.Run = ufw.run
	st := Sync(o)
	if st.Backend != "ufw" || st.Error != "" {
		t.Fatalf("status: %+v", st)
	}
	want := "22/tcp=refused 5432/tcp=foreign 8080/tcp=existing 21115/tcp=existing 25565/tcp=opened 25565/udp=opened 26000/tcp=not-listening 27000/sctp=refused"
	if got := states(st); got != want {
		t.Errorf("states:\n got %s\nwant %s", got, want)
	}
	if len(st.Removed) != 1 || st.Removed[0].Key() != "30000/udp" {
		t.Errorf("stale own rule not removed: %+v", st.Removed)
	}
	calls := strings.Join(ufw.calls, "\n")
	for _, c := range []string{"ufw allow 25565/tcp comment ohg-forward", "ufw allow 25565/udp comment ohg-forward", "ufw delete allow 30000/udp"} {
		if !strings.Contains(calls, c) {
			t.Errorf("missing call %q in:\n%s", c, calls)
		}
	}
	for _, c := range []string{"8080", "21115", "5432", "allow 22/", "26000", "delete allow 8080", "delete allow 22/"} {
		if strings.Contains(strings.ReplaceAll(calls, "ufw status", ""), c) {
			t.Errorf("touched a port it must not: %q in:\n%s", c, calls)
		}
	}
	// the status file is written for ohg
	if s, err := ReadStatus(StatusFile(o.StateDir)); err != nil || s == nil || s.Lookup("25565/tcp").State != StateOpened {
		t.Errorf("status file: %+v %v", s, err)
	}

	// second run: nothing to add, nothing to delete
	ufw.calls = nil
	st = Sync(o)
	for _, c := range ufw.calls {
		if !strings.HasSuffix(c, " status") {
			t.Errorf("second run changed something: %v", ufw.calls)
			break
		}
	}
	if st.Lookup("25565/udp").State != StateOpened {
		t.Errorf("second run: %s", states(st))
	}

	// forward deleted: only our rules go away
	o.ReadDesired = func(string, int) ([]Port, error) { return nil, nil }
	st = Sync(o)
	keys := []string{}
	for _, p := range st.Removed {
		keys = append(keys, p.Key())
	}
	sort.Strings(keys)
	if strings.Join(keys, " ") != "25565/tcp 25565/udp" {
		t.Errorf("removed %v", keys)
	}
	for _, l := range ufw.lines {
		if strings.Contains(l, Marker) {
			t.Errorf("own rule left: %s", l)
		}
	}
	if len(ufw.lines) != 5 {
		t.Errorf("admin rules touched: %v", ufw.lines)
	}
}

// fakeFirewalld simulates firewall-cmd with runtime and permanent ports.
type fakeFirewalld struct {
	runtime, permanent map[string]bool
}

func (f *fakeFirewalld) run(name string, args ...string) (string, error) {
	if name == "ufw" {
		return "Status: inactive\n", nil
	}
	if len(args) == 1 && args[0] == "--state" {
		return "running\n", nil
	}
	set := f.runtime
	if args[0] == "--permanent" {
		set, args = f.permanent, args[1:]
	}
	op, port, _ := strings.Cut(args[0], "=")
	switch op {
	case "--query-port":
		if set[port] {
			return "yes\n", nil
		}
		return "no\n", errors.New("exit status 1")
	case "--add-port":
		set[port] = true
	case "--remove-port":
		delete(set, port)
	}
	return "success\n", nil
}

func TestSyncFirewalld(t *testing.T) {
	fw := &fakeFirewalld{runtime: map[string]bool{"8080/tcp": true}, permanent: map[string]bool{"8080/tcp": true}}
	o := testOptions(t, []Port{{Port: 25565, Proto: "tcp"}, {Port: 8080, Proto: "tcp"}}, []string{"25565/tcp", "8080/tcp"})
	o.Run = fw.run
	st := Sync(o)
	if st.Backend != "firewalld" || states(st) != "8080/tcp=existing 25565/tcp=opened" {
		t.Fatalf("%s %+v", states(st), st)
	}
	if !fw.runtime["25565/tcp"] || !fw.permanent["25565/tcp"] {
		t.Error("port not added runtime and permanently")
	}
	// forward removed: our port goes, the administrator's stays
	o.ReadDesired = func(string, int) ([]Port, error) { return nil, nil }
	st = Sync(o)
	if fw.runtime["25565/tcp"] || fw.permanent["25565/tcp"] || !fw.runtime["8080/tcp"] || !fw.permanent["8080/tcp"] {
		t.Errorf("runtime %v permanent %v", fw.runtime, fw.permanent)
	}
	if len(st.Removed) != 1 {
		t.Errorf("removed %+v", st.Removed)
	}
}

func TestSyncNoFirewall(t *testing.T) {
	o := testOptions(t, []Port{{Port: 25565, Proto: "tcp"}}, []string{"25565/tcp"})
	o.Have = func(string) bool { return false }
	o.Run = func(string, ...string) (string, error) { t.Fatal("no command may run"); return "", nil }
	st := Sync(o)
	if st.Backend != "none" || states(st) != "25565/tcp=no-firewall" {
		t.Errorf("%+v", st)
	}
}

func TestSyncRootOwnedDataDir(t *testing.T) {
	o := testOptions(t, nil, nil)
	o.OwnerUID = func(string) (int, error) { return 0, nil }
	if st := Sync(o); st.Error == "" {
		t.Error("root-owned data dir accepted")
	}
}

func TestListeningPorts(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	hdr := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	write("tcp", hdr+
		"   0: 00000000:63DD 00000000:0000 0A 00000000:00000000 00:00000000 00000000   997        0 1\n"+ // 25565 listen, ohg
		"   1: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2\n"+ // 8080 listen, root
		"   2: 0100007F:6590 0100007F:A1B2 01 00000000:00000000 00:00000000 00000000   997        0 3\n") // established
	write("tcp6", hdr+"   0: 00000000000000000000000000000000:7530 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000   997        0 4\n")
	write("udp", hdr+"  10: 00000000:63DD 00000000:0000 07 00000000:00000000 00:00000000 00000000   997        0 5\n")
	got, err := ListeningPorts(dir, 997)
	if err != nil {
		t.Fatal(err)
	}
	keys := []string{}
	for k := range got {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if strings.Join(keys, " ") != "25565/tcp 25565/udp 30000/tcp" {
		t.Errorf("got %v", keys)
	}
}

func TestWriteDesiredOnlyOnChange(t *testing.T) {
	dir := t.TempDir()
	ports := []Port{{Port: 25565, Proto: "udp"}, {Port: 25565, Proto: "tcp", Name: "minecraft"}}
	if err := WriteDesired(dir, ports, false); err != nil {
		t.Fatal(err)
	}
	fi1, _ := os.Stat(DesiredFile(dir))
	time.Sleep(20 * time.Millisecond)
	if err := WriteDesired(dir, []Port{ports[1], ports[0]}, false); err != nil {
		t.Fatal(err)
	}
	fi2, _ := os.Stat(DesiredFile(dir))
	if !fi1.ModTime().Equal(fi2.ModTime()) {
		t.Error("unchanged list rewritten (would trigger the sync needlessly)")
	}
	data, _ := os.ReadFile(DesiredFile(dir))
	if !strings.Contains(string(data), `"port": 25565`) || strings.Index(string(data), `"tcp"`) > strings.Index(string(data), `"udp"`) {
		t.Errorf("file:\n%s", data)
	}
	if err := WriteDesired(dir, nil, false); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(DesiredFile(dir)); !strings.Contains(string(data), `"ports": []`) {
		t.Errorf("empty list: %s", data)
	}
}

func TestSyncLeavesRulesWhileOhgIsDown(t *testing.T) {
	ufw := &fakeUFW{lines: []string{"25565/tcp                  ALLOW       Anywhere                   # ohg-forward"}}
	o := testOptions(t, []Port{{Port: 25565, Proto: "tcp"}}, nil) // ohg listens on nothing: restarting
	o.Run = ufw.run
	st := Sync(o)
	if st.Error == "" || len(st.Removed) != 0 || len(ufw.lines) != 1 {
		t.Fatalf("rules touched while ohg is down: %+v %v", st, ufw.lines)
	}
	// uninstall: everything of ours goes, even without ohg
	o.RemoveAll = true
	o.ReadDesired = func(string, int) ([]Port, error) { t.Fatal("list read on remove-all"); return nil, nil }
	st = Sync(o)
	if len(st.Removed) != 1 || len(ufw.lines) != 0 {
		t.Errorf("remove-all: %+v %v", st, ufw.lines)
	}
}

func TestWriteDesiredForce(t *testing.T) {
	dir := t.TempDir()
	p := []Port{{Port: 25565, Proto: "tcp"}}
	if err := WriteDesired(dir, p, false); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Hour)
	os.Chtimes(DesiredFile(dir), old, old)
	if err := WriteDesired(dir, p, true); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(DesiredFile(dir)); !fi.ModTime().After(old.Add(time.Minute)) {
		t.Error("forced write did not touch the file (no sync after a restart)")
	}
}
