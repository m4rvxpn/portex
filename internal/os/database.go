// Package osfp implements OS fingerprinting via TCP/IP stack analysis.
// Named "osfp" to avoid collision with the "os" stdlib package.
package osfp

import (
	"bufio"
	"bytes"
	"fmt"
	"strings"
)

// OSRecord is one parsed OS record from nmap-os-db.
type OSRecord struct {
	Name        string
	CPE         string
	Family      string
	Generation  string
	Fingerprint string // the raw FP string
}

// OSDB holds all parsed OS records.
type OSDB struct {
	Records []OSRecord
}

// LoadOSDB parses the nmap-os-db file content.
// The nmap-os-db format is blocks starting with "Fingerprint <name>" followed
// by "Class <vendor> | <OS> | <OS family> | <generation>" and then
// "SEQ(...)" "OPS(...)" "WIN(...)" "ECN(...)" "T1(...)" ... "U1(...)" "IE(...)" lines.
func LoadOSDB(data []byte) (*OSDB, error) {
	db := &OSDB{}

	scanner := bufio.NewScanner(bytes.NewReader(data))

	var current *OSRecord
	var fpLines []string

	flushRecord := func() {
		if current != nil {
			current.Fingerprint = strings.Join(fpLines, "\n")
			db.Records = append(db.Records, *current)
			current = nil
			fpLines = fpLines[:0]
		}
	}

	for scanner.Scan() {
		line := scanner.Text()

		// Skip comments and blank lines (blank lines separate records)
		if line == "" {
			flushRecord()
			continue
		}
		if strings.HasPrefix(line, "#") {
			continue
		}

		if strings.HasPrefix(line, "Fingerprint ") {
			flushRecord()
			name := strings.TrimPrefix(line, "Fingerprint ")
			current = &OSRecord{Name: strings.TrimSpace(name)}
			fpLines = fpLines[:0]
			fpLines = append(fpLines, line)
			continue
		}

		if current == nil {
			continue
		}

		if strings.HasPrefix(line, "Class ") {
			// Format: Class <vendor> | <OS> | <OS family> | <generation>
			rest := strings.TrimPrefix(line, "Class ")
			parts := strings.Split(rest, "|")
			switch len(parts) {
			case 4:
				current.Generation = strings.TrimSpace(parts[3])
				fallthrough
			case 3:
				current.Family = strings.TrimSpace(parts[2])
			}
			fpLines = append(fpLines, line)
			continue
		}

		if strings.HasPrefix(line, "CPE ") {
			current.CPE = strings.TrimSpace(strings.TrimPrefix(line, "CPE "))
			fpLines = append(fpLines, line)
			continue
		}

		// SEQ, OPS, WIN, ECN, T1-T7, U1, IE lines
		fpLines = append(fpLines, line)
	}

	// Flush last record
	flushRecord()

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan os-db: %w", err)
	}

	return db, nil
}
