package headscale

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// State of a supervised headscale process.
type State string

// Process states.
const (
	StateStopped  State = "stopped"
	StateStarting State = "starting"
	StateRunning  State = "running"
	StateCrashed  State = "crashed"
)

// Spec describes how to run one instance.
type Spec struct {
	ID      int64
	Slug    string
	Dir     string
	Port    int
	Config  []byte
	DERPMap []byte // optional
}

// Status is a snapshot of a process state.
type Status struct {
	State     State
	LastError string
	Since     time.Time
	Restarts  int
	PID       int
}

// Manager supervises headscale processes.
type Manager struct {
	bin string
	log *slog.Logger

	// OnReady is called (in a new goroutine) whenever an instance becomes
	// ready after (re)start.
	OnReady func(id int64)

	mu    sync.Mutex
	procs map[int64]*proc
}

// NewManager creates a supervisor using the headscale binary at bin.
func NewManager(bin string, log *slog.Logger) *Manager {
	return &Manager{bin: bin, log: log, procs: map[int64]*proc{}}
}

// Binary returns the headscale binary path.
func (m *Manager) Binary() string { return m.bin }

// CheckBinary verifies that the headscale binary exists and runs.
func (m *Manager) CheckBinary(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, m.bin, "version").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("headscale binary %s not usable: %v", m.bin, err)
	}
	first, _, _ := strings.Cut(strings.TrimSpace(string(out)), "\n")
	return strings.TrimSpace(strings.TrimPrefix(first, "headscale version")), nil
}

type proc struct {
	spec     Spec
	logs     *ring
	stopOnce sync.Once
	stopCh   chan struct{}
	done     chan struct{}

	mu       sync.Mutex
	state    State
	lastErr  string
	since    time.Time
	restarts int
	pid      int
}

func (p *proc) set(s State, errMsg string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.state != s {
		p.since = time.Now()
	}
	p.state = s
	if errMsg != "" || s == StateRunning {
		p.lastErr = errMsg
	}
}

func (p *proc) stopping() bool {
	select {
	case <-p.stopCh:
		return true
	default:
		return false
	}
}

// Start writes the configuration and launches the instance. If it is
// already running it is restarted with the new configuration.
func (m *Manager) Start(spec Spec) error {
	m.Stop(spec.ID)
	if err := os.MkdirAll(spec.Dir, 0o750); err != nil {
		return err
	}
	if err := writeFileAtomic(ConfigPath(spec.Dir), spec.Config, 0o640); err != nil {
		return err
	}
	if spec.DERPMap != nil {
		if err := writeFileAtomic(DERPMapPath(spec.Dir), spec.DERPMap, 0o640); err != nil {
			return err
		}
	}
	p := &proc{
		spec:   spec,
		logs:   newRing(400),
		stopCh: make(chan struct{}),
		done:   make(chan struct{}),
		state:  StateStarting,
		since:  time.Now(),
	}
	m.mu.Lock()
	if old, ok := m.procs[spec.ID]; ok {
		// keep the log history across restarts
		p.logs = old.logs
		p.restarts = old.restarts
	}
	m.procs[spec.ID] = p
	m.mu.Unlock()
	go m.run(p)
	return nil
}

// Stop terminates an instance and waits for it to exit.
func (m *Manager) Stop(id int64) {
	m.mu.Lock()
	p := m.procs[id]
	m.mu.Unlock()
	if p == nil {
		return
	}
	p.stopOnce.Do(func() { close(p.stopCh) })
	<-p.done
}

// StopAll stops every instance.
func (m *Manager) StopAll() {
	m.mu.Lock()
	ids := make([]int64, 0, len(m.procs))
	for id := range m.procs {
		ids = append(ids, id)
	}
	m.mu.Unlock()
	var wg sync.WaitGroup
	for _, id := range ids {
		wg.Add(1)
		go func(id int64) { defer wg.Done(); m.Stop(id) }(id)
	}
	wg.Wait()
}

// Forget removes the bookkeeping of a stopped instance.
func (m *Manager) Forget(id int64) {
	m.Stop(id)
	m.mu.Lock()
	delete(m.procs, id)
	m.mu.Unlock()
}

// Status returns the state of an instance.
func (m *Manager) Status(id int64) Status {
	m.mu.Lock()
	p := m.procs[id]
	m.mu.Unlock()
	if p == nil {
		return Status{State: StateStopped}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return Status{State: p.state, LastError: p.lastErr, Since: p.since, Restarts: p.restarts, PID: p.pid}
}

// Logs returns the recent log lines of an instance.
func (m *Manager) Logs(id int64) []string {
	m.mu.Lock()
	p := m.procs[id]
	m.mu.Unlock()
	if p == nil {
		return nil
	}
	return p.logs.Lines()
}

// WaitReady blocks until the instance is running or ctx expires.
func (m *Manager) WaitReady(ctx context.Context, id int64) error {
	t := time.NewTicker(100 * time.Millisecond)
	defer t.Stop()
	for {
		st := m.Status(id)
		if st.State == StateRunning {
			return nil
		}
		select {
		case <-ctx.Done():
			if st.LastError != "" {
				return fmt.Errorf("headscale not ready: %s", st.LastError)
			}
			return errors.New("headscale not ready (timeout)")
		case <-t.C:
		}
	}
}

func childEnv(dir string) []string {
	var env []string
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "OHG_") || strings.HasPrefix(kv, "HEADSCALE_") || strings.HasPrefix(kv, "TS_") {
			continue
		}
		if strings.HasPrefix(kv, "HOME=") {
			continue
		}
		env = append(env, kv)
	}
	return append(env, "HOME="+dir)
}

func (m *Manager) run(p *proc) {
	defer close(p.done)
	backoff := time.Second
	log := m.log.With("instance", p.spec.Slug)
	for {
		if p.stopping() {
			p.set(StateStopped, "")
			return
		}
		_ = os.Remove(SocketPath(p.spec.Dir))
		cmd := exec.Command(m.bin, "-c", ConfigPath(p.spec.Dir), "serve")
		cmd.Dir = p.spec.Dir
		cmd.Env = childEnv(p.spec.Dir)
		cmd.Stdout = p.logs
		cmd.Stderr = p.logs
		setProcAttr(cmd)
		p.set(StateStarting, "")
		if err := cmd.Start(); err != nil {
			log.Error("headscale start failed", "err", err)
			p.set(StateCrashed, err.Error())
			if !p.sleep(backoff) {
				p.set(StateStopped, "")
				return
			}
			backoff = min(backoff*2, time.Minute)
			continue
		}
		p.mu.Lock()
		p.pid = cmd.Process.Pid
		p.mu.Unlock()
		exited := make(chan error, 1)
		go func() { exited <- cmd.Wait() }()

		readyCtx, cancelReady := context.WithCancel(context.Background())
		go func() {
			if waitHealthy(readyCtx, p.spec.Port, 45*time.Second) {
				p.set(StateRunning, "")
				log.Info("headscale ready", "port", p.spec.Port)
				if m.OnReady != nil {
					go m.OnReady(p.spec.ID)
				}
			}
		}()
		started := time.Now()

		select {
		case err := <-exited:
			cancelReady()
			if p.stopping() {
				p.set(StateStopped, "")
				return
			}
			msg := "headscale exited"
			if err != nil {
				msg += ": " + err.Error()
			}
			if last := p.logs.LastError(); last != "" {
				msg += " – " + last
			}
			log.Warn("headscale exited unexpectedly", "err", err)
			p.mu.Lock()
			p.restarts++
			p.pid = 0
			p.mu.Unlock()
			p.set(StateCrashed, msg)
			if time.Since(started) > 2*time.Minute {
				backoff = time.Second
			}
			if !p.sleep(backoff) {
				p.set(StateStopped, "")
				return
			}
			backoff = min(backoff*2, time.Minute)
		case <-p.stopCh:
			cancelReady()
			terminate(cmd)
			select {
			case <-exited:
			case <-time.After(15 * time.Second):
				_ = cmd.Process.Kill()
				<-exited
			}
			p.mu.Lock()
			p.pid = 0
			p.mu.Unlock()
			p.set(StateStopped, "")
			return
		}
	}
}

func (p *proc) sleep(d time.Duration) bool {
	select {
	case <-time.After(d):
		return true
	case <-p.stopCh:
		return false
	}
}

func waitHealthy(ctx context.Context, port int, timeout time.Duration) bool {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	client := &http.Client{Timeout: 2 * time.Second}
	url := fmt.Sprintf("http://127.0.0.1:%d/health", port)
	for {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		res, err := client.Do(req)
		if err == nil {
			res.Body.Close()
			if res.StatusCode == http.StatusOK {
				return true
			}
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(250 * time.Millisecond):
		}
	}
}

// RunCLI executes the headscale CLI for an instance (it talks to the
// running server via its unix socket) and returns stdout.
func (m *Manager) RunCLI(ctx context.Context, dir string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	full := append([]string{"-c", ConfigPath(dir)}, args...)
	cmd := exec.CommandContext(ctx, m.bin, full...)
	cmd.Dir = dir
	cmd.Env = childEnv(dir)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = strings.TrimSpace(stdout.String())
		}
		return nil, fmt.Errorf("headscale %s: %v: %s", strings.Join(args, " "), err, msg)
	}
	return stdout.Bytes(), nil
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Chmod(tmp, perm); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

// WriteFileAtomic is exported for other packages.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	return writeFileAtomic(path, data, perm)
}

// ring is a thread-safe line ring buffer implementing io.Writer.
type ring struct {
	mu    sync.Mutex
	lines []string
	max   int
	part  []byte
}

func newRing(max int) *ring { return &ring{max: max} }

func (r *ring) Write(b []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.part = append(r.part, b...)
	for {
		i := bytes.IndexByte(r.part, '\n')
		if i < 0 {
			break
		}
		line := strings.TrimRight(string(r.part[:i]), "\r")
		r.part = r.part[i+1:]
		if len(line) > 2000 {
			line = line[:2000]
		}
		r.lines = append(r.lines, stripANSI(line))
		if len(r.lines) > r.max {
			r.lines = r.lines[len(r.lines)-r.max:]
		}
	}
	if len(r.part) > 8192 {
		r.part = r.part[:0]
	}
	return len(b), nil
}

// Lines returns a copy of the buffered lines.
func (r *ring) Lines() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.lines...)
}

// LastError returns the most recent line that looks like an error.
func (r *ring) LastError() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := len(r.lines) - 1; i >= 0 && i >= len(r.lines)-30; i-- {
		l := r.lines[i]
		ll := strings.ToLower(l)
		if strings.Contains(ll, "fatal") || strings.Contains(ll, "error") || strings.Contains(ll, " ftl ") || strings.Contains(ll, " err ") {
			if len(l) > 400 {
				l = l[:400]
			}
			return l
		}
	}
	return ""
}

func stripANSI(s string) string {
	if !strings.Contains(s, "\x1b[") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == 0x1b && i+1 < len(s) && s[i+1] == '[' {
			j := i + 2
			for j < len(s) && (s[j] < 0x40 || s[j] > 0x7e) {
				j++
			}
			i = j
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
