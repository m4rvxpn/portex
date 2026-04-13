package proxy

import (
	"fmt"
	"net/url"
	"os"
	"strings"
)

// FromEnv reads proxy configuration from environment variables.
// Checks (in order): PORTEX_PROXY, SOCKS5_PROXY, HTTP_PROXY, http_proxy.
// Returns an empty string if no proxy is configured.
func FromEnv() string {
	vars := []string{"PORTEX_PROXY", "SOCKS5_PROXY", "HTTP_PROXY", "http_proxy"}
	for _, v := range vars {
		if val := os.Getenv(v); val != "" {
			return val
		}
	}
	return ""
}

// Parse parses a proxy URL string into scheme and address.
// Supports: socks5://host:port, http://host:port
func Parse(proxyURL string) (scheme, addr string, err error) {
	if proxyURL == "" {
		return "", "", fmt.Errorf("empty proxy URL")
	}

	// Add a scheme if missing so url.Parse can work.
	raw := proxyURL
	if !strings.Contains(raw, "://") {
		raw = "socks5://" + raw
	}

	u, err := url.Parse(raw)
	if err != nil {
		return "", "", fmt.Errorf("invalid proxy URL %q: %w", proxyURL, err)
	}

	scheme = strings.ToLower(u.Scheme)
	switch scheme {
	case "socks5", "socks5h", "http", "https":
	default:
		return "", "", fmt.Errorf("unsupported proxy scheme %q in %q", scheme, proxyURL)
	}

	host := u.Hostname()
	port := u.Port()
	if host == "" {
		return "", "", fmt.Errorf("missing host in proxy URL %q", proxyURL)
	}
	if port == "" {
		switch scheme {
		case "http", "https":
			port = "8080"
		default:
			port = "1080"
		}
	}

	addr = host + ":" + port
	return scheme, addr, nil
}
