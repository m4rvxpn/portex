package service

import (
	"bufio"
	"bytes"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// ServiceProbe holds one parsed probe entry.
type ServiceProbe struct {
	Proto       string // "TCP" | "UDP"
	Name        string // probe name (e.g., "GetRequest")
	Payload     []byte // raw bytes to send (after unescaping \r\n etc.)
	Matches     []MatchRule
	SoftMatches []MatchRule
	Rarity      int
	Ports       []int // hint ports for this probe
	SSLPorts    []int
	TotalWaitMS int
	TCPWrapped  bool
}

// MatchRule is one match/softmatch directive.
type MatchRule struct {
	Service string
	Pattern string
	Flags   string // "i" for case-insensitive
	regex   *regexp.Regexp
	// capture groups map to: p/ (product), v/ (version), i/ (info), h/ (hostname), o/ (OS), d/ (device)
	Product string // template with $1 $2 etc.
	Version string
	Info    string
	OS      string
	CPE     string
}

// ProbeDB holds parsed probe data for all protocols.
type ProbeDB struct {
	Probes []ServiceProbe
	byPort map[int][]int // port → indices into Probes (for fast lookup)
	mu     sync.RWMutex
}

// LoadProbeDB parses the nmap-service-probes file content.
func LoadProbeDB(data []byte) (*ProbeDB, error) {
	db := &ProbeDB{
		byPort: make(map[int][]int),
	}

	scanner := bufio.NewScanner(bytes.NewReader(data))
	var current *ServiceProbe

	for scanner.Scan() {
		line := scanner.Text()

		// Skip comments and blank lines
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}

		switch fields[0] {
		case "Probe":
			// Flush previous probe
			if current != nil {
				db.Probes = append(db.Probes, *current)
			}
			if len(fields) < 4 {
				current = nil
				continue
			}
			proto := fields[1]
			name := fields[2]
			// payload is q|...|  (or other delimiters)
			payload, err := parsePayload(fields[3])
			if err != nil {
				// skip bad probe line
				current = nil
				continue
			}
			current = &ServiceProbe{
				Proto:   proto,
				Name:    name,
				Payload: payload,
				Rarity:  5, // default rarity
			}

		case "match", "softmatch":
			if current == nil {
				continue
			}
			rule, err := parseMatchRule(line)
			if err != nil {
				continue
			}
			if fields[0] == "match" {
				current.Matches = append(current.Matches, rule)
			} else {
				current.SoftMatches = append(current.SoftMatches, rule)
			}

		case "ports":
			if current == nil || len(fields) < 2 {
				continue
			}
			current.Ports = parsePorts(fields[1])

		case "sslports":
			if current == nil || len(fields) < 2 {
				continue
			}
			current.SSLPorts = parsePorts(fields[1])

		case "rarity":
			if current == nil || len(fields) < 2 {
				continue
			}
			if n, err := strconv.Atoi(fields[1]); err == nil {
				current.Rarity = n
			}

		case "totalwaitms":
			if current == nil || len(fields) < 2 {
				continue
			}
			if n, err := strconv.Atoi(fields[1]); err == nil {
				current.TotalWaitMS = n
			}

		case "tcpwrapped":
			if current != nil {
				current.TCPWrapped = true
			}

		default:
			// Unknown directive — skip gracefully
		}
	}

	// Flush last probe
	if current != nil {
		db.Probes = append(db.Probes, *current)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan error: %w", err)
	}

	// Build port index
	for idx, probe := range db.Probes {
		for _, p := range probe.Ports {
			db.byPort[p] = append(db.byPort[p], idx)
		}
	}

	return db, nil
}

// FindProbesForPort returns probes relevant to the given port, sorted by rarity.
func (db *ProbeDB) FindProbesForPort(port int, proto string) []ServiceProbe {
	db.mu.RLock()
	defer db.mu.RUnlock()

	protoUpper := strings.ToUpper(proto)

	// Collect indices matching by port hint or by protocol
	seen := make(map[int]struct{})
	var indices []int

	if idxs, ok := db.byPort[port]; ok {
		for _, i := range idxs {
			if db.Probes[i].Proto == protoUpper || protoUpper == "" {
				seen[i] = struct{}{}
				indices = append(indices, i)
			}
		}
	}

	// Also include probes with no port hints (generic probes)
	for i, probe := range db.Probes {
		if _, already := seen[i]; already {
			continue
		}
		if len(probe.Ports) == 0 && (probe.Proto == protoUpper || protoUpper == "") {
			indices = append(indices, i)
		}
	}

	// Sort by rarity ascending (lower rarity = more common = try first)
	sort.Slice(indices, func(a, b int) bool {
		return db.Probes[indices[a]].Rarity < db.Probes[indices[b]].Rarity
	})

	result := make([]ServiceProbe, 0, len(indices))
	for _, i := range indices {
		result = append(result, db.Probes[i])
	}
	return result
}

// MatchBanner matches a banner against all match rules and returns the best Match.
// Returns nil if no match found.
func (db *ProbeDB) MatchBanner(banner []byte, probes []ServiceProbe) *Match {
	db.mu.RLock()
	defer db.mu.RUnlock()

	// Try hard matches first
	for _, probe := range probes {
		for _, rule := range probe.Matches {
			if m := tryMatch(banner, rule, probe.Name, 8); m != nil {
				return m
			}
		}
	}

	// Then soft matches
	for _, probe := range probes {
		for _, rule := range probe.SoftMatches {
			if m := tryMatch(banner, rule, probe.Name, 4); m != nil {
				return m
			}
		}
	}

	return nil
}

// tryMatch attempts to match banner against a rule, returning a Match or nil.
func tryMatch(banner []byte, rule MatchRule, probeName string, baseConf int) *Match {
	if rule.regex == nil {
		return nil
	}
	subs := rule.regex.FindSubmatch(banner)
	if subs == nil {
		return nil
	}

	// Expand capture group templates
	expand := func(tmpl string) string {
		if tmpl == "" {
			return ""
		}
		result := tmpl
		for i, sub := range subs {
			if i == 0 {
				continue
			}
			result = strings.ReplaceAll(result, fmt.Sprintf("$%d", i), string(sub))
		}
		return result
	}

	return &Match{
		Service: rule.Service,
		Version: expand(rule.Version),
		Product: expand(rule.Product),
		OS:      expand(rule.OS),
		CPE:     expand(rule.CPE),
		Banner:  string(banner),
		Probe:   probeName,
		Conf:    baseConf,
	}
}

// parsePayload parses nmap probe payload strings like q|GET / HTTP/1.0\r\n\r\n|
func parsePayload(s string) ([]byte, error) {
	if len(s) < 3 {
		return nil, fmt.Errorf("payload too short: %q", s)
	}

	// Must start with q followed by a delimiter
	if s[0] != 'q' {
		return nil, fmt.Errorf("payload doesn't start with q: %q", s)
	}

	delim := rune(s[1])
	rest := s[2:]
	end := strings.IndexRune(rest, delim)
	if end < 0 {
		return nil, fmt.Errorf("missing closing delimiter in: %q", s)
	}

	raw := rest[:end]
	return unescapePayload(raw), nil
}

// unescapePayload converts nmap-style escape sequences to raw bytes.
func unescapePayload(s string) []byte {
	var buf bytes.Buffer
	i := 0
	for i < len(s) {
		if s[i] == '\\' && i+1 < len(s) {
			switch s[i+1] {
			case 'r':
				buf.WriteByte('\r')
				i += 2
			case 'n':
				buf.WriteByte('\n')
				i += 2
			case 't':
				buf.WriteByte('\t')
				i += 2
			case '\\':
				buf.WriteByte('\\')
				i += 2
			case '0':
				buf.WriteByte(0)
				i += 2
			case 'x':
				if i+3 < len(s) {
					hex := s[i+2 : i+4]
					if n, err := strconv.ParseUint(hex, 16, 8); err == nil {
						buf.WriteByte(byte(n))
						i += 4
						continue
					}
				}
				buf.WriteByte(s[i])
				i++
			default:
				buf.WriteByte(s[i])
				i++
			}
		} else {
			buf.WriteByte(s[i])
			i++
		}
	}
	return buf.Bytes()
}

// parseMatchRule parses a match or softmatch line.
// Format: match <service> m[<flags>]/<pattern>/[<flags>] [p/<product>] [v/<version>] [i/<info>] [o/<os>] [cpe:/<cpe>]
func parseMatchRule(line string) (MatchRule, error) {
	parts := strings.Fields(line)
	if len(parts) < 3 {
		return MatchRule{}, fmt.Errorf("match line too short: %q", line)
	}

	rule := MatchRule{
		Service: parts[1],
	}

	// Parse the pattern field: m[<predelim>][flags]<delim><pattern><delim>[flags]
	patternStr := parts[2]
	if len(patternStr) < 2 || patternStr[0] != 'm' {
		return MatchRule{}, fmt.Errorf("invalid match pattern: %q", patternStr)
	}

	// Check for flags before delimiter: m|...| or m%i|...|
	idx := 1
	// Optional flags before the delimiter
	var preFlags string
	for idx < len(patternStr) && patternStr[idx] != '|' && patternStr[idx] != '/' && patternStr[idx] != '%' {
		// collect pre-delimiter flags if any (nmap uses m|...|i form mostly)
		break
	}
	_ = preFlags

	if idx >= len(patternStr) {
		return MatchRule{}, fmt.Errorf("no delimiter in pattern: %q", patternStr)
	}

	delim := patternStr[idx]
	rest := patternStr[idx+1:]
	end := strings.IndexByte(rest, delim)
	if end < 0 {
		return MatchRule{}, fmt.Errorf("no closing delimiter in pattern: %q", patternStr)
	}

	pattern := rest[:end]
	afterDelim := rest[end+1:]

	// afterDelim may contain flags like "i"
	flags := afterDelim
	rule.Pattern = pattern
	rule.Flags = flags

	// Build regexp
	regexStr := pattern
	regexFlags := "(?s)" // dot-all by default
	if strings.Contains(flags, "i") {
		regexFlags = "(?si)"
	}
	compiled, err := regexp.Compile(regexFlags + regexStr)
	if err != nil {
		// If regex fails to compile, skip this rule
		return MatchRule{}, fmt.Errorf("compile regex %q: %w", regexStr, err)
	}
	rule.regex = compiled

	// Parse remaining optional fields: p/.../ v/.../ i/.../ o/.../ cpe:/.../ h/.../
	remaining := strings.Join(parts[3:], " ")
	rule.Product = extractField(remaining, "p")
	rule.Version = extractField(remaining, "v")
	rule.Info = extractField(remaining, "i")
	rule.OS = extractField(remaining, "o")
	rule.CPE = extractCPE(remaining)

	return rule, nil
}

// extractField extracts a value from nmap match info fields like p/value/ or v/value/
func extractField(s, key string) string {
	prefix := key + "/"
	idx := strings.Index(s, prefix)
	if idx < 0 {
		return ""
	}
	start := idx + len(prefix)
	// Find closing /
	end := strings.Index(s[start:], "/")
	if end < 0 {
		return s[start:]
	}
	return s[start : start+end]
}

// extractCPE extracts a CPE value from cpe:/... field
func extractCPE(s string) string {
	const prefix = "cpe:/"
	idx := strings.Index(s, prefix)
	if idx < 0 {
		return ""
	}
	start := idx + len(prefix) - 1 // include the /
	rest := s[start:]
	// CPE ends at a space or end of string
	end := strings.IndexByte(rest, ' ')
	if end < 0 {
		return rest
	}
	return rest[:end]
}

// parsePorts parses a comma-separated port list like "80,443,8080"
func parsePorts(s string) []int {
	var ports []int
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if n, err := strconv.Atoi(part); err == nil {
			ports = append(ports, n)
		}
	}
	return ports
}
