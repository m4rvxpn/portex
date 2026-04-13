package packet

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/m4rvxpn/portex/internal/scanner"
)

// FTPScanner performs FTP bounce scans (-b).
// Connects to an FTP server and uses the PORT command to proxy connections
// to the target host/port.
type FTPScanner struct {
	ftpHost string
	ftpPort int
	timeout time.Duration
}

// NewFTPScanner creates a new FTPScanner.
func NewFTPScanner(ftpHost string, ftpPort int, timeout time.Duration) *FTPScanner {
	return &FTPScanner{
		ftpHost: ftpHost,
		ftpPort: ftpPort,
		timeout: timeout,
	}
}

// Scan performs an FTP bounce scan to check targetIP:targetPort.
func (s *FTPScanner) Scan(ctx context.Context, targetIP net.IP, targetPort int) (state scanner.PortState, reason string, rtt time.Duration, err error) {
	start := time.Now()

	dialCtx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	d := net.Dialer{}
	addr := fmt.Sprintf("%s:%d", s.ftpHost, s.ftpPort)
	conn, err := d.DialContext(dialCtx, "tcp", addr)
	if err != nil {
		return scanner.StateUnknown, "ftp-connect-fail", time.Since(start), err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(s.timeout))

	reader := bufio.NewReader(conn)

	// Read 220 banner
	banner, err := readFTPResponse(reader)
	if err != nil || !strings.HasPrefix(banner, "220") {
		return scanner.StateUnknown, "ftp-banner-fail", time.Since(start), fmt.Errorf("bad FTP banner: %s", banner)
	}

	// Authenticate
	if err := ftpSend(conn, "USER anonymous\r\n"); err != nil {
		return scanner.StateUnknown, "ftp-user-fail", time.Since(start), err
	}
	resp, _ := readFTPResponse(reader)
	_ = resp

	if err := ftpSend(conn, "PASS portex@\r\n"); err != nil {
		return scanner.StateUnknown, "ftp-pass-fail", time.Since(start), err
	}
	resp, _ = readFTPResponse(reader)
	_ = resp

	// Build PORT command: h1,h2,h3,h4,p1,p2
	ip4 := targetIP.To4()
	if ip4 == nil {
		return scanner.StateUnknown, "no-ipv4", time.Since(start), fmt.Errorf("FTP bounce requires IPv4 target")
	}
	p1 := targetPort / 256
	p2 := targetPort % 256
	portCmd := fmt.Sprintf("PORT %d,%d,%d,%d,%d,%d\r\n",
		ip4[0], ip4[1], ip4[2], ip4[3], p1, p2)

	if err := ftpSend(conn, portCmd); err != nil {
		return scanner.StateUnknown, "ftp-port-fail", time.Since(start), err
	}
	resp, _ = readFTPResponse(reader)
	if !strings.HasPrefix(resp, "200") {
		return scanner.StateClosed, "ftp-port-reject", time.Since(start), nil
	}

	// Send LIST to trigger connection to target
	if err := ftpSend(conn, "LIST\r\n"); err != nil {
		return scanner.StateUnknown, "ftp-list-fail", time.Since(start), err
	}

	resp, _ = readFTPResponse(reader)
	rtt = time.Since(start)

	switch {
	case strings.HasPrefix(resp, "150") || strings.HasPrefix(resp, "125"):
		return scanner.StateOpen, "ftp-open", rtt, nil
	case strings.HasPrefix(resp, "425") || strings.HasPrefix(resp, "550"):
		return scanner.StateClosed, "ftp-refused", rtt, nil
	default:
		return scanner.StateFiltered, "ftp-no-response", rtt, nil
	}
}

// readFTPResponse reads a single FTP response line.
func readFTPResponse(r *bufio.Reader) (string, error) {
	line, err := r.ReadString('\n')
	return strings.TrimSpace(line), err
}

// ftpSend sends a command string to the FTP connection.
func ftpSend(conn net.Conn, cmd string) error {
	_, err := fmt.Fprint(conn, cmd)
	return err
}
