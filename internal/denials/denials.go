// Package denials keeps what the sandbox refused, so --explain can plan from
// more than the run in front of you. One JSON object per line, next to the
// proxy's event log, one project per file.
//
// The kernel log is the source and it is a window: ask after it closes and the
// answer is gone, or it answers with every confined process on the machine from
// the same period. One run is one sample of what a program touches, and a
// control fitted to a sample both over-permits and breaks on the next run. The
// union over the runs you have made is the actual specification, and this file
// is what makes the union available.
//
// Targets and process names come from the kernel log, which is written by
// whatever asked. JSON encoding keeps them from breaking the file; readers
// re-check the process name before printing it.
package denials

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"time"
)

// Row is one distinct refusal as one run saw it: the process the kernel logged
// it against, the operation, the target, and how many times that run asked.
type Row struct {
	Time time.Time `json:"t"`
	// Command is the program the run was started for (raptor), which is what a
	// later run of the same program matches against. Agent keeps the exact
	// label of the run that saw it (raptor-30920).
	Command string `json:"command"`
	Agent   string `json:"agent,omitempty"`
	// RunID names one run within the file, so ten runs of one agent label are
	// still counted as ten.
	RunID  string `json:"run_id,omitempty"`
	Proc   string `json:"proc,omitempty"`
	Op     string `json:"op"`
	Target string `json:"target"`
	Count  int    `json:"count,omitempty"`
}

// Valid says whether a row read back can be planned from. A file is user-owned
// and can be edited by anything with your uid, so a row without the two fields
// the plan needs is junk rather than evidence.
func (r Row) Valid() bool { return r.Op != "" && r.Target != "" }

// Write appends rows, one Write per line so concurrent appenders cannot
// interleave inside a line. A nil slice writes nothing.
func Write(w io.Writer, rows []Row) error {
	for _, r := range rows {
		if !r.Valid() {
			continue
		}
		if r.Time.IsZero() {
			r.Time = time.Now()
		}
		r.Time = r.Time.UTC()
		b, err := json.Marshal(r)
		if err != nil {
			return err
		}
		b = append(b, '\n')
		if _, err := w.Write(b); err != nil {
			return err
		}
	}
	return nil
}

// Read returns the file's rows and how many lines were skipped: a truncated
// tail, a line someone edited, a row missing what it needs. The count is
// reported rather than swallowed because a plan built on half the record has to
// say it was.
func Read(r io.Reader) (rows []Row, skipped int) {
	br := bufio.NewReaderSize(r, 64*1024)
	for {
		line, err := br.ReadBytes('\n')
		if len(bytes.TrimSpace(line)) > 0 {
			var row Row
			if json.Unmarshal(bytes.TrimSpace(line), &row) != nil || !row.Valid() {
				skipped++
			} else {
				rows = append(rows, row)
			}
		}
		if err != nil {
			if err != io.EOF {
				skipped++
			}
			return rows, skipped
		}
	}
}

// Select keeps the rows a run may plan from: this program's own, from since
// onwards. Agent labels carry a pid, so they differ per run and cannot be the
// match; Command is the stable half.
func Select(rows []Row, command string, since time.Time) []Row {
	var out []Row
	for _, r := range rows {
		if r.Command != command || r.Time.Before(since) {
			continue
		}
		out = append(out, r)
	}
	return out
}

// Runs is how many separate runs contributed these rows, which is what the
// report says the plan was drawn from.
func Runs(rows []Row) int {
	seen := map[string]bool{}
	for _, r := range rows {
		key := r.RunID
		if key == "" {
			key = r.Agent
		}
		if key == "" {
			key = r.Time.UTC().Format(time.RFC3339)
		}
		seen[key] = true
	}
	return len(seen)
}

// String is for a line of debug output; the report prints fields, not rows.
func (r Row) String() string {
	return fmt.Sprintf("%s %s %s x%d", r.Proc, r.Op, r.Target, r.Count)
}
