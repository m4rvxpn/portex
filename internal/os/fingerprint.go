package osfp

import (
	"context"
	"net"
	"sort"

	"github.com/m4rvxpn/portex/internal/scanner"
)

// Fingerprinter performs OS fingerprinting.
type Fingerprinter struct {
	db        *OSDB
	collector *Collector
}

// NewFingerprinter creates a new Fingerprinter.
func NewFingerprinter(db *OSDB, collector *Collector) *Fingerprinter {
	return &Fingerprinter{
		db:        db,
		collector: collector,
	}
}

// Fingerprint runs OS probes and returns OS matches sorted by accuracy.
func (f *Fingerprinter) Fingerprint(ctx context.Context, target net.IP, openPort, closedPort int) ([]scanner.OSMatch, error) {
	metrics, err := f.collector.Collect(ctx, target, openPort, closedPort)
	if err != nil {
		// Return heuristic-only results if collection fails
		return f.heuristicMatches(nil), nil
	}

	return f.heuristicMatches(metrics), nil
}

// heuristicMatches applies TTL and window-based heuristics to produce OS candidates.
func (f *Fingerprinter) heuristicMatches(metrics *TCPIPMetrics) []scanner.OSMatch {
	if metrics == nil {
		return nil
	}

	var matches []scanner.OSMatch

	ttl := metrics.IPTTL
	win := metrics.TCPWindow

	switch {
	case ttl >= 60 && ttl <= 70 && win == 65535:
		// Linux with large window
		matches = append(matches, scanner.OSMatch{
			Name:       "Linux 4.x/5.x",
			Accuracy:   70,
			CPE:        "cpe:/o:linux:linux_kernel:5",
			Family:     "Linux",
			Generation: "5.X",
		})
		matches = append(matches, scanner.OSMatch{
			Name:       "Linux 3.x",
			Accuracy:   60,
			CPE:        "cpe:/o:linux:linux_kernel:3",
			Family:     "Linux",
			Generation: "3.X",
		})

	case ttl >= 60 && ttl <= 70:
		// Generic Linux/Unix
		matches = append(matches, scanner.OSMatch{
			Name:       "Linux 4.x/5.x",
			Accuracy:   60,
			CPE:        "cpe:/o:linux:linux_kernel:5",
			Family:     "Linux",
			Generation: "5.X",
		})
		matches = append(matches, scanner.OSMatch{
			Name:       "FreeBSD",
			Accuracy:   40,
			CPE:        "cpe:/o:freebsd:freebsd",
			Family:     "BSD",
			Generation: "",
		})

	case ttl >= 120 && ttl <= 135 && win == 65535:
		// Windows 7/10 with large window
		matches = append(matches, scanner.OSMatch{
			Name:       "Microsoft Windows 10",
			Accuracy:   65,
			CPE:        "cpe:/o:microsoft:windows_10",
			Family:     "Windows",
			Generation: "10",
		})
		matches = append(matches, scanner.OSMatch{
			Name:       "Microsoft Windows 7",
			Accuracy:   55,
			CPE:        "cpe:/o:microsoft:windows_7",
			Family:     "Windows",
			Generation: "7",
		})

	case ttl >= 120 && ttl <= 135 && win == 8192:
		// Windows XP
		matches = append(matches, scanner.OSMatch{
			Name:       "Microsoft Windows XP",
			Accuracy:   65,
			CPE:        "cpe:/o:microsoft:windows_xp",
			Family:     "Windows",
			Generation: "XP",
		})

	case ttl >= 120 && ttl <= 135:
		// Generic Windows
		matches = append(matches, scanner.OSMatch{
			Name:       "Microsoft Windows",
			Accuracy:   60,
			CPE:        "cpe:/o:microsoft:windows",
			Family:     "Windows",
			Generation: "",
		})

	case ttl >= 250 && ttl <= 255:
		// Cisco or network device
		matches = append(matches, scanner.OSMatch{
			Name:     "Cisco IOS",
			Accuracy: 70,
			CPE:      "cpe:/o:cisco:ios",
			Family:   "IOS",
		})
		matches = append(matches, scanner.OSMatch{
			Name:     "Solaris",
			Accuracy: 40,
			CPE:      "cpe:/o:sun:solaris",
			Family:   "Solaris",
		})

	default:
		// Unknown TTL — try window-based heuristics only
		if win == 65535 {
			matches = append(matches, scanner.OSMatch{
				Name:     "Linux/Unix",
				Accuracy: 30,
				CPE:      "cpe:/o:linux:linux_kernel",
				Family:   "Linux",
			})
		} else if win == 8192 {
			matches = append(matches, scanner.OSMatch{
				Name:     "Microsoft Windows",
				Accuracy: 30,
				CPE:      "cpe:/o:microsoft:windows",
				Family:   "Windows",
			})
		}
	}

	// If we have OSDB records, try to enrich matches with better names
	if f.db != nil && len(f.db.Records) > 0 {
		for i, m := range matches {
			for _, rec := range f.db.Records {
				if rec.Family == m.Family && rec.Generation == m.Generation {
					matches[i].Name = rec.Name
					if rec.CPE != "" {
						matches[i].CPE = rec.CPE
					}
					break
				}
			}
		}
	}

	// Sort by accuracy descending
	sort.Slice(matches, func(i, j int) bool {
		return matches[i].Accuracy > matches[j].Accuracy
	})

	return matches
}
