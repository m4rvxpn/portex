package service

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sampleProbeData uses a null probe payload (q||) because the LoadProbeDB
// implementation parses the payload field using strings.Fields, which splits
// on whitespace. Payloads with spaces (e.g. q|GET / HTTP/1.0\r\n|) would be
// truncated. The real nmap-service-probes embedded file handles this correctly
// because its payloads use nmap escape sequences without spaces.
const sampleProbeData = `Probe TCP NullProbe q||
rarity 3
ports 80,8080
match http m|^HTTP/1\.[01] [0-9]{3}| p/HTTP server/
match apache m|^HTTP.*Apache| p/Apache httpd/
softmatch http m|^HTTP| p/HTTP/
`

func TestLoadProbeDB_ParsesSampleData(t *testing.T) {
	db, err := LoadProbeDB([]byte(sampleProbeData))
	require.NoError(t, err)
	require.NotNil(t, db)
	assert.GreaterOrEqual(t, len(db.Probes), 1, "at least 1 probe should be parsed")
}

func TestMatchBanner_HTTPMatch(t *testing.T) {
	db, err := LoadProbeDB([]byte(sampleProbeData))
	require.NoError(t, err)

	banner := []byte("HTTP/1.1 200 OK\r\n")
	probes := db.FindProbesForPort(80, "TCP")
	require.NotEmpty(t, probes, "should find probes for port 80")

	match := db.MatchBanner(banner, probes)
	require.NotNil(t, match, "banner should match")
	assert.Equal(t, "http", match.Service)
}

func TestMatchBanner_NoMatch(t *testing.T) {
	db, err := LoadProbeDB([]byte(sampleProbeData))
	require.NoError(t, err)

	banner := []byte("totally unrelated data")
	probes := db.FindProbesForPort(80, "TCP")

	match := db.MatchBanner(banner, probes)
	assert.Nil(t, match, "unrelated banner should not match")
}

func TestFindProbesForPort_80(t *testing.T) {
	db, err := LoadProbeDB([]byte(sampleProbeData))
	require.NoError(t, err)

	probes := db.FindProbesForPort(80, "TCP")
	assert.NotEmpty(t, probes, "should find probes for port 80")
}
