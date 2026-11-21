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
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
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
	// KindDns is one name resolution the sandbox relayed to the proxy. It is
	// gated by the allow-list like a connection, because a query name is
	// itself information leaving the sandbox.
	KindDns = "dns"
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
	mu      sync.Mutex
	w       io.Writer
	agent   string
	dropped atomic.Int64
	// Log receives one line the first time a write fails, so a full disk is
	// noticed rather than silently emptying the audit trail. nil keeps the
	// writer silent. Set it before the first Write, as proxy.Server.Log is.
	Log io.Writer
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
	if err == nil {
		b = append(b, '\n')
		w.mu.Lock()
		_, err = w.w.Write(b)
		w.mu.Unlock()
	}
	if err != nil {
		w.failed(err)
	}
}

// failed counts one lost event. This is the record the console asks questions
// of afterwards, so a write that fails on a full disk says so once, on Log,
// and every failure after it is counted rather than dropped on the floor.
func (w *Writer) failed(err error) {
	if w.dropped.Add(1) == 1 && w.Log != nil {
		fmt.Fprintf(w.Log, "sandboxcheckr: event log write failed: %v (further failures are counted, not reported)\n", err)
	}
}

// Dropped is how many events could not be written. A shortfall nobody can see
// is not an audit trail, so the proxy exit summary and the console show it.
func (w *Writer) Dropped() int64 {
	if w == nil {
		return 0
	}
	return w.dropped.Load()
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

// MaxLine is the largest event line Read accepts; a longer one is junk, since
// one event is one JSON object. Console callers tailing a log use the same cap
// so the two never disagree about what is lost.
const MaxLine = 1 << 20

// Read parses an event log, skipping lines that are not events. It returns
// the events in file order and the number of lines skipped. The count is the
// console's only integrity signal, so nothing may be lost without adding to it.
func Read(r io.Reader) ([]Event, int) {
	var out []Event
	skipped := 0
	br := bufio.NewReaderSize(r, 64*1024)
	for {
		line, tooLong, err := readLine(br)
		if tooLong {
			// Past the cap the line is junk; count it and move on.
			skipped++
		} else if len(bytes.TrimSpace(line)) > 0 {
			if e, ok := ParseLine(line); ok {
				out = append(out, e)
			} else {
				skipped++
			}
		}
		if err != nil {
			// A read error that is not the end of the file lost whatever was
			// left; say so in the only channel the console has. A line already
			// counted as too long is one loss, not two.
			if err != io.EOF && !tooLong {
				skipped++
			}
			return out, skipped
		}
	}
}

// readLine returns the next line of br without its newline, whether it ran
// past MaxLine, and the reader's error. Reading with ReadSlice rather than a
// Scanner is what lets one oversized line be dropped instead of ending the
// scan: a bufio.Scanner stops at ErrTooLong and every event after it is lost
// without a trace.
func readLine(br *bufio.Reader) (line []byte, tooLong bool, err error) {
	for {
		chunk, e := br.ReadSlice('\n')
		line = append(line, chunk...)
		if len(line) > MaxLine {
			tooLong = true
		}
		if e == bufio.ErrBufferFull {
			continue
		}
		if e != nil {
			return line, tooLong, e
		}
		return line[:len(line)-1], tooLong, nil
	}
}

// ParseLine parses one event line and reports whether it held an event.
// Callers tailing a log use it instead of Read: Read copies the reader's
// buffer per call, which makes following a busy log quadratic and allocates
// twice for every event.
func ParseLine(line []byte) (Event, bool) {
	var e Event
	if err := json.Unmarshal(bytes.TrimSpace(line), &e); err != nil || e.Kind == "" {
		return Event{}, false
	}
	return e, true
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
