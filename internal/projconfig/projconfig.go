// Package projconfig reads a project's sandboxcheckr.toml: the baseline
// policy "sandboxcheckr run" applies when invoked in that directory.
//
// The file is a strict TOML subset, chosen so the parser stays small enough
// to audit and every mistake is a loud error rather than a silent default:
//
//	# comments, blank lines
//	key = value            # value is a bool, a string, or a one-line array
//	allow = ["localhost", "127.0.0.1"]
//	observe = false
//
// No tables, no multiline arrays, no dates. Unknown keys, duplicate keys and
// type mismatches are errors with line numbers, so a typo in the file can
// never quietly widen (or narrow) what the sandbox permits.
package projconfig

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Config is the parsed policy file. Field names match run's flags; lists are
// baselines the command line adds to, scalars are defaults the command line
// overrides.
type Config struct {
	Allows, Rules, Ports, PrivHosts []string
	PassEnv, RO, RW                 []string
	Observe                         bool
	NoCanary, CanaryKill            bool
	NoAgentAuth                     bool
	Events, Agent, DenyFile         string
}

// Name is the file name read from the project directory.
const Name = "sandboxcheckr.toml"

// Error is a parse or schema failure, with the file line for fixing it.
type Error struct {
	Line int
	Msg  string
}

func (e *Error) Error() string {
	return fmt.Sprintf("%s:%d: %s", Name, e.Line, e.Msg)
}

func errf(line int, format string, args ...any) error {
	return &Error{Line: line, Msg: fmt.Sprintf(format, args...)}
}

// keySpec describes one accepted key: how to store it and which type it takes.
type keySpec struct {
	kind  string // "strings" or "bool" or "path" or "text"
	apply func(c *Config, line int, v value) error
}

var specs = map[string]keySpec{
	"allow":              stringsKey(func(c *Config, v []string) { c.Allows = v }),
	"rule":               stringsKey(func(c *Config, v []string) { c.Rules = v }),
	"allow-port":         stringsKey(func(c *Config, v []string) { c.Ports = v }),
	"allow-private-host": stringsKey(func(c *Config, v []string) { c.PrivHosts = v }),
	"pass-env":           stringsKey(func(c *Config, v []string) { c.PassEnv = v }),
	"ro":                 pathsKey(func(c *Config, v []string) { c.RO = v }),
	"rw":                 pathsKey(func(c *Config, v []string) { c.RW = v }),
	"observe":            boolKey(func(c *Config, v bool) { c.Observe = v }),
	"no-canary":          boolKey(func(c *Config, v bool) { c.NoCanary = v }),
	"canary-kill":        boolKey(func(c *Config, v bool) { c.CanaryKill = v }),
	"no-agent-auth":      boolKey(func(c *Config, v bool) { c.NoAgentAuth = v }),
	"events":             pathKey(func(c *Config, v string) { c.Events = v }),
	"agent":              textKey(func(c *Config, v string) { c.Agent = v }),
	"deny-file":          pathKey(func(c *Config, v string) { c.DenyFile = v }),
}

func stringsKey(set func(*Config, []string)) keySpec {
	return keySpec{kind: "strings", apply: func(c *Config, _ int, v value) error {
		if v.kind != "strings" {
			return fmt.Errorf("expects an array of strings")
		}
		set(c, v.strs)
		return nil
	}}
}

// pathsKey is stringsKey for directories: each element gets ~ expansion,
// because the shell that expands ~ in command-line flags never sees this file.
func pathsKey(set func(*Config, []string)) keySpec {
	return keySpec{kind: "strings", apply: func(c *Config, _ int, v value) error {
		if v.kind != "strings" {
			return fmt.Errorf("expects an array of strings")
		}
		for i, p := range v.strs {
			v.strs[i] = expandTilde(p)
		}
		set(c, v.strs)
		return nil
	}}
}

func boolKey(set func(*Config, bool)) keySpec {
	return keySpec{kind: "bool", apply: func(c *Config, _ int, v value) error {
		if v.kind != "bool" {
			return fmt.Errorf("expects true or false")
		}
		set(c, v.boolean)
		return nil
	}}
}

func pathKey(set func(*Config, string)) keySpec {
	return keySpec{kind: "path", apply: func(c *Config, _ int, v value) error {
		if v.kind != "text" {
			return fmt.Errorf("expects a string")
		}
		set(c, expandTilde(v.text))
		return nil
	}}
}

func textKey(set func(*Config, string)) keySpec {
	return keySpec{kind: "text", apply: func(c *Config, _ int, v value) error {
		if v.kind != "text" {
			return fmt.Errorf("expects a string")
		}
		set(c, v.text)
		return nil
	}}
}

// expandTilde resolves a leading ~ or ~/ against the user's home directory.
// The shell does this for command-line flags, but a config file has no shell
// to do it, and an unexpanded ~ would silently point inside the project.
func expandTilde(p string) string {
	if p != "~" && !strings.HasPrefix(p, "~/") {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return p
	}
	return filepath.Join(home, strings.TrimPrefix(p, "~"))
}

type value struct {
	kind    string // "bool", "text", "strings"
	boolean bool
	text    string
	strs    []string
}

// Load reads and parses path. A missing file is not an error: it returns nil,
// and the caller proceeds with flag-only configuration.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	c := &Config{}
	seen := map[string]bool{}
	for i, raw := range strings.Split(string(data), "\n") {
		line := i + 1
		text := stripComment(raw)
		text = strings.TrimSpace(text)
		if text == "" {
			continue
		}
		key, rest, found := strings.Cut(text, "=")
		if !found {
			return nil, errf(line, "expected key = value")
		}
		key = strings.TrimSpace(key)
		if key == "" {
			return nil, errf(line, "empty key")
		}
		spec, ok := specs[key]
		if !ok {
			return nil, errf(line, "unknown key %q (accepted: %s)", key, strings.Join(sortedKeys(), ", "))
		}
		if seen[key] {
			return nil, errf(line, "duplicate key %q", key)
		}
		seen[key] = true
		v, err := parseValue(strings.TrimSpace(rest), line)
		if err != nil {
			return nil, err
		}
		if err := spec.apply(c, line, v); err != nil {
			return nil, errf(line, "%s: %v", key, err)
		}
	}
	return c, nil
}

// sortedKeys lists accepted keys for the unknown-key error, stable order.
func sortedKeys() []string {
	out := make([]string, 0, len(specs))
	for k := range specs {
		out = append(out, k)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// stripComment removes a trailing # comment, honouring quotes so a # inside a
// string survives.
func stripComment(line string) string {
	inDouble, inSingle := false, false
	for i := 0; i < len(line); i++ {
		switch line[i] {
		case '\\':
			if inDouble {
				i++ // skip the escaped character
			}
		case '"':
			if !inSingle {
				inDouble = !inDouble
			}
		case '\'':
			if !inDouble {
				inSingle = !inSingle
			}
		case '#':
			if !inDouble && !inSingle {
				return line[:i]
			}
		}
	}
	return line
}

// parseValue parses one value: bool, quoted string, or single-line array.
func parseValue(s string, line int) (value, error) {
	switch {
	case s == "true":
		return value{kind: "bool", boolean: true}, nil
	case s == "false":
		return value{kind: "bool", boolean: false}, nil
	case strings.HasPrefix(s, "\""), strings.HasPrefix(s, "'"):
		text, rest, err := parseString(s, line)
		if err != nil {
			return value{}, err
		}
		if strings.TrimSpace(rest) != "" {
			return value{}, errf(line, "unexpected text after string: %q", strings.TrimSpace(rest))
		}
		return value{kind: "text", text: text}, nil
	case strings.HasPrefix(s, "["):
		return parseArray(s, line)
	default:
		return value{}, errf(line, "cannot parse value %q (use true, false, \"quoted\", or [\"array\"])", s)
	}
}

// parseString parses one quoted string, returning the string and the rest of
// the line (for array element parsing).
func parseString(s string, line int) (string, string, error) {
	quote := s[0]
	var sb strings.Builder
	for i := 1; i < len(s); i++ {
		c := s[i]
		if quote == '\'' {
			if c == '\'' {
				return sb.String(), s[i+1:], nil
			}
			sb.WriteByte(c)
			continue
		}
		if c == '\\' {
			if i+1 >= len(s) {
				return "", "", errf(line, "dangling escape in string")
			}
			i++
			switch s[i] {
			case '"', '\\':
				sb.WriteByte(s[i])
			case 'n':
				sb.WriteByte('\n')
			case 't':
				sb.WriteByte('\t')
			default:
				return "", "", errf(line, "unsupported escape \\%c", s[i])
			}
			continue
		}
		if c == '"' {
			return sb.String(), s[i+1:], nil
		}
		sb.WriteByte(c)
	}
	return "", "", errf(line, "unterminated string")
}

// parseArray parses ["a", 'b', 8000] on one line: quoted strings and bare
// non-negative integers (ports read better unquoted).
func parseArray(s string, line int) (value, error) {
	rest := strings.TrimSpace(s[1:])
	out := []string{}
	if strings.HasPrefix(rest, "]") {
		return value{kind: "strings", strs: out}, nil
	}
	for {
		rest = strings.TrimSpace(rest)
		if rest == "" {
			return value{}, errf(line, "unterminated array (missing ])")
		}
		var text string
		if strings.HasPrefix(rest, "\"") || strings.HasPrefix(rest, "'") {
			var rest2 string
			var err error
			text, rest2, err = parseString(rest, line)
			if err != nil {
				return value{}, err
			}
			rest = strings.TrimSpace(rest2)
		} else {
			i := 0
			for i < len(rest) && rest[i] >= '0' && rest[i] <= '9' {
				i++
			}
			if i == 0 {
				return value{}, errf(line, "array elements must be quoted strings or integers")
			}
			text, rest = rest[:i], strings.TrimSpace(rest[i:])
		}
		out = append(out, text)
		switch {
		case strings.HasPrefix(rest, ","):
			rest = rest[1:]
		case strings.HasPrefix(rest, "]"):
			return value{kind: "strings", strs: out}, nil
		case rest == "":
			return value{}, errf(line, "unterminated array (missing ])")
		default:
			return value{}, errf(line, "expected , or ] in array")
		}
	}
}
