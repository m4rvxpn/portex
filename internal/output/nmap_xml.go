package output

import (
	"encoding/xml"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/m4rvxpn/portex/internal/scanner"
)

// nmapPort holds port-level data for the XML output.
type nmapPort struct {
	Port     int
	Protocol string
	State    string
	Service  string
	Product  string
	Version  string
}

// nmapHost holds in-progress XML data for one host.
type nmapHost struct {
	addr  string
	ports []nmapPort
}

// NmapXMLWriter writes nmap-compatible XML output.
type NmapXMLWriter struct {
	w     io.Writer
	mu    sync.Mutex
	hosts map[string]*nmapHost
}

// NewNmapXMLWriter returns a new NmapXMLWriter writing to w.
func NewNmapXMLWriter(w io.Writer) *NmapXMLWriter {
	return &NmapXMLWriter{
		w:     w,
		hosts: make(map[string]*nmapHost),
	}
}

// WritePort accumulates the port result for the final XML document.
func (n *NmapXMLWriter) WritePort(r scanner.PortResult) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	h, ok := n.hosts[r.Target]
	if !ok {
		h = &nmapHost{addr: r.Target}
		n.hosts[r.Target] = h
	}

	p := nmapPort{
		Port:     r.Port,
		Protocol: r.Protocol,
		State:    string(r.State),
	}
	if r.Service != nil {
		p.Service = r.Service.Service
		p.Product = r.Service.Product
		p.Version = r.Service.Version
	}
	h.ports = append(h.ports, p)
	return nil
}

// WriteResult writes the complete nmap-compatible XML document to the writer.
func (n *NmapXMLWriter) WriteResult(_ *scanner.ScanResult) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	if _, err := fmt.Fprintf(n.w, `<?xml version="1.0" encoding="UTF-8"?>`+"\n"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(n.w, "<!DOCTYPE nmaprun>\n"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(n.w, `<nmaprun scanner="portex" version="1.0">`+"\n"); err != nil {
		return err
	}

	for _, h := range n.hosts {
		if err := n.writeHost(h); err != nil {
			return err
		}
	}

	_, err := fmt.Fprintf(n.w, "</nmaprun>\n")
	return err
}

// writeHost writes a single <host> element. Must be called with mu held.
func (n *NmapXMLWriter) writeHost(h *nmapHost) error {
	addrType := "ipv4"

	if _, err := fmt.Fprintf(n.w, "  <host>\n"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(n.w, "    <address addr=%s addrtype=%s/>\n",
		xmlAttr(h.addr), xmlAttr(addrType)); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(n.w, "    <ports>\n"); err != nil {
		return err
	}

	for _, p := range h.ports {
		proto := p.Protocol
		if proto == "" {
			proto = "tcp"
		}
		reason := "syn-ack"
		if p.State != string(scanner.StateOpen) {
			reason = "no-response"
		}

		if _, err := fmt.Fprintf(n.w, "      <port protocol=%s portid=%s>\n",
			xmlAttr(proto), xmlAttr(fmt.Sprintf("%d", p.Port))); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(n.w, "        <state state=%s reason=%s/>\n",
			xmlAttr(p.State), xmlAttr(reason)); err != nil {
			return err
		}
		if p.Service != "" || p.Product != "" || p.Version != "" {
			if _, err := fmt.Fprintf(n.w, "        <service name=%s product=%s version=%s/>\n",
				xmlAttr(p.Service), xmlAttr(p.Product), xmlAttr(p.Version)); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintf(n.w, "      </port>\n"); err != nil {
			return err
		}
	}

	if _, err := fmt.Fprintf(n.w, "    </ports>\n"); err != nil {
		return err
	}
	_, err := fmt.Fprintf(n.w, "  </host>\n")
	return err
}

// Close flushes the XML document.
func (n *NmapXMLWriter) Close() error {
	return nil
}

// xmlAttr returns an XML-safe double-quoted attribute value using xml.EscapeText.
func xmlAttr(s string) string {
	var buf strings.Builder
	buf.WriteByte('"')
	if err := xml.EscapeText(&buf, []byte(s)); err != nil {
		// Fallback: escape manually.
		buf.Reset()
		buf.WriteByte('"')
		buf.WriteString(s)
	}
	buf.WriteByte('"')
	return buf.String()
}
