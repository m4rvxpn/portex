package llm

import (
	"strings"

	"github.com/m4rvxpn/portex/internal/scanner"
)

// cveEntry maps a service name pattern and optional version prefix to known CVEs.
type cveEntry struct {
	servicePattern string // lowercase substring match on service name
	versionPrefix  string // version must start with this (empty = any version)
	cves           []string
}

// knownCVEs is a curated list of high-impact CVEs for common services.
var knownCVEs = []cveEntry{
	{
		servicePattern: "apache",
		versionPrefix:  "2.4.49",
		cves:           []string{"CVE-2021-41773", "CVE-2021-42013"},
	},
	{
		servicePattern: "apache",
		versionPrefix:  "2.4.50",
		cves:           []string{"CVE-2021-42013"},
	},
	{
		servicePattern: "apache",
		versionPrefix:  "2.4",
		cves:           []string{"CVE-2022-22720", "CVE-2021-41524"},
	},
	{
		servicePattern: "openssh",
		versionPrefix:  "", // any OpenSSH below 8.0 via version check
		cves:           []string{"CVE-2019-6111", "CVE-2018-15473"},
	},
	{
		servicePattern: "ssh",
		versionPrefix:  "openssh_7",
		cves:           []string{"CVE-2019-6111", "CVE-2018-15473"},
	},
	{
		servicePattern: "nginx",
		versionPrefix:  "1.13",
		cves:           []string{"CVE-2017-7529"},
	},
	{
		servicePattern: "nginx",
		versionPrefix:  "1.12",
		cves:           []string{"CVE-2017-7529"},
	},
	{
		servicePattern: "mysql",
		versionPrefix:  "5.",
		cves:           []string{"CVE-2016-6662", "CVE-2016-6663", "CVE-2012-2122"},
	},
	{
		servicePattern: "proftpd",
		versionPrefix:  "1.3.5",
		cves:           []string{"CVE-2015-3306"},
	},
	{
		servicePattern: "vsftpd",
		versionPrefix:  "2.3.4",
		cves:           []string{"CVE-2011-2523"},
	},
	{
		servicePattern: "samba",
		versionPrefix:  "3.",
		cves:           []string{"CVE-2017-7494"},
	},
	{
		servicePattern: "samba",
		versionPrefix:  "4.",
		cves:           []string{"CVE-2017-7494", "CVE-2021-44142"},
	},
	{
		servicePattern: "elasticsearch",
		versionPrefix:  "",
		cves:           []string{"CVE-2015-1427", "CVE-2014-3120"},
	},
	{
		servicePattern: "redis",
		versionPrefix:  "",
		cves:           []string{"CVE-2022-0543", "CVE-2015-4335"},
	},
	{
		servicePattern: "tomcat",
		versionPrefix:  "9.",
		cves:           []string{"CVE-2020-1938", "CVE-2019-0232"},
	},
	{
		servicePattern: "tomcat",
		versionPrefix:  "8.",
		cves:           []string{"CVE-2020-1938", "CVE-2019-0232", "CVE-2017-12617"},
	},
}

// CVESuggestion generates CVE hints based on service+version without LLM.
// Returns a deduplicated list of CVE IDs matching the port's service and version.
func CVESuggestion(port scanner.PortResult) []string {
	if port.Service == nil {
		return nil
	}

	svcLower := strings.ToLower(port.Service.Service + " " + port.Service.Product)
	verLower := strings.ToLower(port.Service.Version)

	seen := make(map[string]bool)
	var results []string

	for _, entry := range knownCVEs {
		if !strings.Contains(svcLower, entry.servicePattern) {
			continue
		}
		if entry.versionPrefix != "" && !strings.HasPrefix(verLower, strings.ToLower(entry.versionPrefix)) {
			continue
		}
		for _, cve := range entry.cves {
			if !seen[cve] {
				seen[cve] = true
				results = append(results, cve)
			}
		}
	}

	return results
}
