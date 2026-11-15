package runenv

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"runtime/debug"
	"sync"
	"time"
)

// Hard upper bounds for external probes. Callers of DetectWith may shorten
// them (tests do), but never lengthen them.
const (
	maxCommandTimeout = 2 * time.Second // any external command
	maxIMDSTimeout    = 1 * time.Second // the whole IMDSv2 exchange
	maxOutputBytes    = 1 << 20         // cap for command output and file reads
	maxIMDSBodyBytes  = 4 << 10         // cap for one IMDS response body
	defaultIMDSBase   = "http://169.254.169.254"
)

// FileReader reads small host files such as /proc/cpuinfo or DMI entries.
type FileReader interface {
	ReadFile(path string) ([]byte, error)
}

// CmdResult is the captured output of a finished command.
type CmdResult struct {
	Stdout []byte
	Stderr []byte
}

// Commander runs an external command and returns its output. Output must be
// returned even when the command exits non-zero, because tools such as
// systemd-detect-virt print their answer and exit 1. Implementations must
// honor ctx. Detect also bounds every call itself, so a misbehaving
// implementation cannot block it.
type Commander interface {
	Run(ctx context.Context, name string, args ...string) (CmdResult, error)
}

// HTTPDoer performs one HTTP request. *http.Client satisfies it.
type HTTPDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// Env bundles every side effect Detect depends on, so tests can inject
// fixtures. The zero value of each field selects the real implementation.
type Env struct {
	OS        string     // runtime.GOOS
	Arch      string     // runtime.GOARCH
	NumCPU    func() int // runtime.NumCPU
	Files     FileReader // real file system
	Exec      Commander  // os/exec
	HTTP      HTTPDoer   // client without proxy for the IMDS endpoint
	LookPath  func(string) (string, error)
	Getenv    func(string) string
	BuildInfo func() (*debug.BuildInfo, bool)
	Now       func() time.Time

	CommandTimeout time.Duration // per external command, capped at 2 s
	IMDSTimeout    time.Duration // whole IMDSv2 exchange, capped at 1 s
	IMDSBase       string        // IMDS base URL, default http://169.254.169.254
}

// DefaultEnv returns the real environment.
func DefaultEnv() Env {
	return Env{}.withDefaults()
}

func (e Env) withDefaults() Env {
	if e.OS == "" {
		e.OS = runtime.GOOS
	}
	if e.Arch == "" {
		e.Arch = runtime.GOARCH
	}
	if e.NumCPU == nil {
		e.NumCPU = runtime.NumCPU
	}
	if e.Files == nil {
		e.Files = osFiles{}
	}
	if e.Exec == nil {
		e.Exec = execRunner{}
	}
	if e.HTTP == nil {
		e.HTTP = newIMDSClient()
	}
	if e.LookPath == nil {
		e.LookPath = exec.LookPath
	}
	if e.Getenv == nil {
		e.Getenv = os.Getenv
	}
	if e.BuildInfo == nil {
		e.BuildInfo = debug.ReadBuildInfo
	}
	if e.Now == nil {
		e.Now = time.Now
	}
	if e.CommandTimeout <= 0 || e.CommandTimeout > maxCommandTimeout {
		e.CommandTimeout = maxCommandTimeout
	}
	if e.IMDSTimeout <= 0 || e.IMDSTimeout > maxIMDSTimeout {
		e.IMDSTimeout = maxIMDSTimeout
	}
	if e.IMDSBase == "" {
		e.IMDSBase = defaultIMDSBase
	}
	return e
}

// readFile reads a file and returns its content, or "" when it cannot be read.
func (e Env) readFile(path string) (string, bool) {
	data, err := e.Files.ReadFile(path)
	if err != nil {
		return "", false
	}
	return string(data), true
}

// run executes a command with the command timeout. The call returns when the
// command finishes or the deadline passes, whichever comes first, even if the
// Commander ignores its context.
func (e Env) run(ctx context.Context, name string, args ...string) (CmdResult, error) {
	ctx, cancel := context.WithTimeout(ctx, e.CommandTimeout)
	defer cancel()

	type outcome struct {
		res CmdResult
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				done <- outcome{err: errors.New("command runner panicked")}
			}
		}()
		res, err := e.Exec.Run(ctx, name, args...)
		done <- outcome{res, err}
	}()

	select {
	case o := <-done:
		return o.res, o.err
	case <-ctx.Done():
		select {
		case o := <-done: // finished at the same moment
			return o.res, o.err
		default:
		}
		return CmdResult{}, ctx.Err()
	}
}

// httpResult is a fully read HTTP response.
type httpResult struct {
	Status int
	Body   []byte
}

// do sends a request and reads at most maxIMDSBodyBytes of the body. It is
// bounded by ctx even if the HTTPDoer ignores it.
func (e Env) do(ctx context.Context, req *http.Request) (httpResult, error) {
	type outcome struct {
		res httpResult
		err error
	}
	done := make(chan outcome, 1)
	req = req.WithContext(ctx)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				done <- outcome{err: errors.New("http client panicked")}
			}
		}()
		resp, err := e.HTTP.Do(req)
		if err != nil {
			done <- outcome{err: err}
			return
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxIMDSBodyBytes))
		done <- outcome{httpResult{resp.StatusCode, body}, err}
	}()

	select {
	case o := <-done:
		return o.res, o.err
	case <-ctx.Done():
		return httpResult{}, ctx.Err()
	}
}

// parallel runs fns concurrently and waits for all of them. A panic inside
// one probe is contained, so a broken probe can never fail the run.
func parallel(fns ...func()) {
	var wg sync.WaitGroup
	wg.Add(len(fns))
	for _, fn := range fns {
		go func() {
			defer wg.Done()
			defer func() { _ = recover() }()
			fn()
		}()
	}
	wg.Wait()
}

// osFiles is the real FileReader.
type osFiles struct{}

func (osFiles) ReadFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, maxOutputBytes))
}

// execRunner is the real Commander.
type execRunner struct{}

func (execRunner) Run(ctx context.Context, name string, args ...string) (CmdResult, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	stdout := &cappedBuffer{limit: maxOutputBytes}
	stderr := &cappedBuffer{limit: maxOutputBytes}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")
	// A killed shell wrapper can leave grandchildren holding the pipes.
	// WaitDelay makes Wait return anyway shortly after the context ends.
	cmd.WaitDelay = 200 * time.Millisecond
	err := cmd.Run()
	return CmdResult{Stdout: stdout.Bytes(), Stderr: stderr.Bytes()}, err
}

// cappedBuffer keeps at most limit bytes and silently drops the rest, so a
// chatty process is never blocked by a full pipe.
type cappedBuffer struct {
	buf   bytes.Buffer
	limit int
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if room := c.limit - c.buf.Len(); room > 0 {
		if len(p) > room {
			c.buf.Write(p[:room])
		} else {
			c.buf.Write(p)
		}
	}
	return len(p), nil
}

func (c *cappedBuffer) Bytes() []byte { return c.buf.Bytes() }

// newIMDSClient returns an HTTP client for the link-local metadata endpoint.
// It never uses a proxy, never reuses connections and dials with a short
// timeout.
func newIMDSClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Proxy:                 nil,
			DialContext:           (&net.Dialer{Timeout: maxIMDSTimeout}).DialContext,
			DisableKeepAlives:     true,
			ResponseHeaderTimeout: maxIMDSTimeout,
		},
	}
}
