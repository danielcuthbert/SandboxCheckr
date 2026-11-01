// Package events is the proxy's structured record of what each sandboxed
// agent tried to reach: one JSON object per line, appended as it happens.
//
// The proxy's text log is for a person watching one run. This is for asking
// questions afterwards, across runs and across agents — which agent went
// looking for a URL shortener, which hosts did two agents both use, what did
// this one try after it was refused. The console (sandboxcheckr console) reads
// it.
//
// Every string in an event came from the sandboxed program: a hostname it
// asked for, a path it requested. Treat them as hostile. JSON encoding keeps
// them from breaking the file; Clean keeps them from reaching a terminal.
package events

import (
	"bufio"
	"encoding/json"
	"io"
	"strings"
	"sync"
	"time"
	"unicode"
)

// Kinds of event.
const (
	// KindConnect is a destination decision: one per CONNECT or plain request.
	KindConnect = "connect"
	// KindRequest is one request the proxy could see: plain HTTP, or a --rule
	// host it TLS-inspected.
	KindRequest = "request"
	// KindWrite is the first data-sending request to a host.
	KindWrite = "write"
	// KindUpload is a host passing the heavy-upload threshold.
	KindUpload = "upload"
	// KindClose carries the byte counts for a finished connection.
	KindClose  = "close"
	KindCanary = "canary"
)

// Decisions.
const (
	Allow   = "allow"
	Deny    = "deny"
	Observe = "observe" // permitted in observe mode; would be denied when enforcing
)

// Event is one line of the log.
type Event struct {
	Time     time.Time `json:"t"`
	Agent    string    `json:"agent,omitempty"`
	Kind     string    `json:"kind"`
	Decision string    `json:"decision,omitempty"`
	Host     string    `json:"host"`
	Port     string    `json:"port,omitempty"`
	Method   string    `json:"method,omitempty"`
	Path     string    `json:"path,omitempty"`
	// Relay names the store-or-forward class of Host, if it has one.
	Relay string `json:"relay,omitempty"`
	// Fetcher marks a host that fetches any URL it is given.
	Fetcher    bool   `json:"fetcher,omitempty"`
	ModelAPI   bool   `json:"model_api,omitempty"`
	Reason     string `json:"reason,omitempty"`
	Canary     string `json:"canary,omitempty"`
	RunID      string `json:"run_id,omitempty"`
	Confidence string `json:"confidence,omitempty"`
	Sent       int64  `json:"sent,omitempty"`
	Recv       int64  `json:"recv,omitempty"`
}

// Writer appends events for one agent. A nil *Writer discards everything, so
// callers need no "is logging on" checks.
type Writer struct {
	mu    sync.Mutex
	w     io.Writer
	agent string
}

// NewWriter returns a Writer that labels every event with agent.
func NewWriter(w io.Writer, agent string) *Writer {
	return &Writer{w: w, agent: AgentLabel(agent)}
}

// Write appends e. Each event is written with a single Write call, so several
// proxies appending to one O_APPEND file do not interleave inside a line.
func (w *Writer) Write(e Event) {
	if w == nil || w.w == nil {
		return
	}
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	e.Time = e.Time.UTC()
	e.Agent = w.agent
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	b = append(b, '\n')
	w.mu.Lock()
	defer w.mu.Unlock()
	_, _ = w.w.Write(b)
}

// AgentLabel reduces a label to letters, digits and . _ - so it can be shown
// and typed safely; anything else becomes '-'. Empty stays empty.
func AgentLabel(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r < 128 && (unicode.IsLetter(r) || unicode.IsDigit(r)), r == '.', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
		if b.Len() >= 64 {
			break
		}
	}
	return b.String()
}

// Read parses an event log, skipping lines that are not events. It returns
// the events in file order and the number of lines skipped.
func Read(r io.Reader) ([]Event, int) {
	var out []Event
	skipped := 0
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		line := sc.Bytes()
		if len(strings.TrimSpace(string(line))) == 0 {
			continue
		}
		var e Event
		if err := json.Unmarshal(line, &e); err != nil || e.Kind == "" {
			skipped++
			continue
		}
		out = append(out, e)
	}
	return out, skipped
}

// Clean makes an untrusted string safe to print: control and format
// characters (escape sequences, bidi overrides) become '?', and anything over
// max runes is cut with an ellipsis. max <= 0 means no limit.
func Clean(s string, max int) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if max > 0 && n >= max {
			b.WriteString("…")
			break
		}
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf) || r == unicode.ReplacementChar {
			r = '?'
		}
		b.WriteRune(r)
		n++
	}
	return b.String()
}
