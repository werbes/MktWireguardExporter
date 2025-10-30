package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Program purpose:
// - Read wg.rsc (MikroTik RouterOS export) to extract WireGuard peer entries.
// - Read wg.conf (a known-good client config) to obtain constant values used for all clients
//   like ListenPort and the server's PublicKey.
// - Generate one Windows .cmd script per peer named after the peer IP (client-address without /32),
//   which builds a .conf with echo lines, moves it into WireGuard's folder, and installs it as a service.

func main() {
	cwd, _ := os.Getwd()

	// Input files at project root by default
	rscPath := filepath.Join(cwd, "wg.rsc")
	confPath := filepath.Join(cwd, "wg.conf")

	base, err := parseBaseConf(confPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing wg.conf: %v\n", err)
		os.Exit(1)
	}

	peers, err := parseRouterOSPeers(rscPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing wg.rsc: %v\n", err)
		os.Exit(1)
	}

	if len(peers) == 0 {
		fmt.Fprintln(os.Stderr, "No peers found in wg.rsc (/interface wireguard peers)")
		os.Exit(1)
	}

	// Generate one .cmd per peer
	for _, p := range peers {
		if p.ClientAddress == "" || p.PrivateKey == "" || p.PresharedKey == "" || p.EndpointAddress == "" || p.EndpointPort == "" {
			// Skip incomplete entries
			continue
		}
		ip := ipOnly(p.ClientAddress) // strip /CIDR
		if ip == "" {
			continue
		}

		// Build AllowedIPs: prefer RouterOS allowed-address; reorder so /32 is last
		allowed := p.AllowedAddress
		if allowed == "" {
			// Fallback: try to compose from wg.conf AllowedIPs by replacing client /32 if present
			if base.AllowedIPs != "" {
				// If base contains any /32, replace with this client's /32
				parts := splitCSV(base.AllowedIPs)
				for i := range parts {
					if strings.HasSuffix(parts[i], "/32") {
						parts[i] = p.ClientAddress
					}
				}
				allowed = strings.Join(parts, ",")
			} else {
				allowed = p.ClientAddress
			}
		}
		allowed = reorderAllowedIPs(allowed)

		script, err := renderCmd(ip, cmdData{
			ListenPort:   base.ListenPort,
			PrivateKey:   p.PrivateKey,
			Address:      p.ClientAddress,
			DNS:          coalesce(p.ClientDNS, base.DNS),
			PublicKey:    base.ServerPublicKey, // server's public key used in [Peer]
			AllowedIPs:   allowed,
			PresharedKey: p.PresharedKey,
			Endpoint:     fmt.Sprintf("%s:%s", p.EndpointAddress, p.EndpointPort),
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Skipping %s: %v\n", ip, err)
			continue
		}

		outPath := filepath.Join(cwd, ip+".que")
		if err := os.WriteFile(outPath, []byte(script), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing %s: %v\n", outPath, err)
			continue
		}
		fmt.Printf("Wrote %s\n", outPath)
	}
}

// BaseConf holds constants from wg.conf
type BaseConf struct {
	ListenPort      string
	ServerPublicKey string // [Peer] PublicKey (the server's)
	DNS             string // optional fallback if RouterOS lacks client-dns
	AllowedIPs      string // optional template
}

func parseBaseConf(path string) (BaseConf, error) {
	f, err := os.Open(path)
	if err != nil {
		return BaseConf{}, err
	}
	defer f.Close()

	var b BaseConf
	s := bufio.NewScanner(f)
	inPeer := false
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			inPeer = strings.EqualFold(line, "[Peer]")
			continue
		}
		key, val, ok := splitKV(line)
		if !ok {
			continue
		}
		switch strings.ToLower(key) {
		case "listenport":
			b.ListenPort = val
		case "dns":
			b.DNS = val
		case "publickey":
			if inPeer {
				b.ServerPublicKey = val
			}
		case "allowedips":
			if inPeer {
				b.AllowedIPs = val
			}
		}
	}
	if err := s.Err(); err != nil {
		return BaseConf{}, err
	}
	if b.ServerPublicKey == "" {
		return b, errors.New("wg.conf missing [Peer] PublicKey (server public key)")
	}
	// ListenPort is optional for clients but include if present
	return b, nil
}

// RouterOS peer entry from wg.rsc
type Peer struct {
	Name            string
	ClientAddress   string
	ClientDNS       string
	EndpointAddress string
	EndpointPort    string
	PrivateKey      string
	PublicKey       string
	PresharedKey    string
	AllowedAddress  string
}

func parseRouterOSPeers(path string) ([]Peer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	lines := splitLines(string(data))
	// First, join backslash-continued lines
	joined := joinContinuations(lines)

	// Find the peers section
	inPeers := false
	var peers []Peer
	for i := 0; i < len(joined); i++ {
		line := strings.TrimSpace(joined[i])
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "/interface wireguard peers") {
			inPeers = true
			continue
		}
		if strings.HasPrefix(line, "/") { // another section starts
			inPeers = false
		}
		if !inPeers {
			continue
		}
		if strings.HasPrefix(line, "add ") {
			p := parsePeerAddLine(line)
			if p != nil {
				peers = append(peers, *p)
			}
		}
	}
	return peers, nil
}

func parsePeerAddLine(line string) *Peer {
	// remove leading 'add '
	rest := strings.TrimSpace(strings.TrimPrefix(line, "add "))
	if rest == "" {
		return nil
	}
	// Split into tokens by spaces, but honor quotes
	tokens := splitFieldsPreserveQuotes(rest)
	if len(tokens) == 0 {
		return nil
	}

	// Combine tokens robustly:
	// Treat only tokens of the form key=... (where key is [A-Za-z0-9-]+ and token does not start with '"')
	// as the start of a field. If the value part after '=' is empty, absorb subsequent tokens as the value
	// until the next key-token appears. This handles both quoted (may contain '=') and unquoted continuations.
	var combined []string

	isKeyToken := func(tok string) bool {
		if strings.HasPrefix(tok, "\"") {
			return false
		}
		eq := strings.IndexByte(tok, '=')
		if eq <= 0 {
			return false
		}
		left := tok[:eq]
		for i := 0; i < len(left); i++ {
			c := left[i]
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-') {
				return false
			}
		}
		return true
	}

	for i := 0; i < len(tokens); i++ {
		t := tokens[i]
		if !isKeyToken(t) {
			// not a key token; skip (it will be absorbed by a preceding key if appropriate)
			continue
		}
		eq := strings.IndexByte(t, '=')
		key := t[:eq]
		val := t[eq+1:]
		if val == "" {
			// absorb following tokens until next key token
			for i+1 < len(tokens) && !isKeyToken(tokens[i+1]) {
				i++
				next := strings.TrimSpace(tokens[i])
				if val != "" {
					val += " "
				}
				val += next
			}
		}
		combined = append(combined, key+"="+val)
	}

	kv := map[string]string{}
	for _, t := range combined {
		if eq := strings.IndexByte(t, '='); eq > 0 {
			k := t[:eq]
			v := t[eq+1:]
			v = trimQuotes(v)
			kv[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
		}
	}

	p := &Peer{
		Name:            kv["name"],
		ClientAddress:   firstNonEmpty(kv["client-address"], kv["address"], kv["clientaddress"]),
		ClientDNS:       firstNonEmpty(kv["client-dns"], kv["dns"], kv["clientdns"]),
		EndpointAddress: firstNonEmpty(kv["endpoint-address"], kv["endpoint"], kv["endpointaddress"]),
		EndpointPort:    firstNonEmpty(kv["endpoint-port"], kv["endpointport"]),
		PrivateKey:      kv["private-key"],
		PublicKey:       kv["public-key"],
		PresharedKey:    kv["preshared-key"],
		AllowedAddress:  firstNonEmpty(kv["allowed-address"], kv["allowedaddress"]),
	}
	// Some exports might use responder=yes with no private-key (server side only) — skip those
	if p.ClientAddress == "" || p.PrivateKey == "" || p.PresharedKey == "" {
		// Debug: show which keys were parsed for this line
		var keys []string
		for k := range kv {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		fmt.Fprintf(os.Stderr, "DEBUG skip: have-keys=%v client-address='%s' priv?%v psk?%v\n", keys, p.ClientAddress, p.PrivateKey != "", p.PresharedKey != "")
		fmt.Fprintf(os.Stderr, "DEBUG tokens=%v\n", tokens)
		fmt.Fprintf(os.Stderr, "DEBUG combined=%v\n", combined)
		return nil
	}
	return p
}

// Rendering

type cmdData struct {
	ListenPort   string
	PrivateKey   string
	Address      string
	DNS          string
	PublicKey    string
	AllowedIPs   string
	PresharedKey string
	Endpoint     string
}

func renderCmd(ip string, d cmdData) (string, error) {
	if ip == "" {
		return "", errors.New("empty ip")
	}
	conf := fmt.Sprintf("%s.conf", ip)
	appendOp := ">>" // use append after the first line

	var b strings.Builder
	// Ensure CRLF endings for Windows .cmd readability
	crlf := "\r\n"

	// Start building the .cmd content
	b.WriteString(fmt.Sprintf("echo [Interface] > %s%s", conf, crlf))
	if d.ListenPort != "" {
		b.WriteString(fmt.Sprintf("echo ListenPort = %s %s %s%s", d.ListenPort, appendOp, conf, crlf))
	}
	if d.PrivateKey != "" {
		b.WriteString(fmt.Sprintf("echo PrivateKey = %s %s %s%s", d.PrivateKey, appendOp, conf, crlf))
	}
	if d.Address != "" {
		b.WriteString(fmt.Sprintf("echo Address = %s %s %s%s", d.Address, appendOp, conf, crlf))
	}
	if d.DNS != "" {
		b.WriteString(fmt.Sprintf("echo DNS = %s %s %s%s", d.DNS, appendOp, conf, crlf))
	}
	// Blank line
	b.WriteString(fmt.Sprintf("echo. %s %s%s", appendOp, conf, crlf))

	b.WriteString(fmt.Sprintf("echo [Peer] %s %s%s", appendOp, conf, crlf))
	if d.PublicKey != "" {
		b.WriteString(fmt.Sprintf("echo PublicKey = %s %s %s%s", d.PublicKey, appendOp, conf, crlf))
	}
	if d.AllowedIPs != "" {
		b.WriteString(fmt.Sprintf("echo AllowedIPs = %s %s %s%s", d.AllowedIPs, appendOp, conf, crlf))
	}
	if d.PresharedKey != "" {
		b.WriteString(fmt.Sprintf("echo PresharedKey = %s %s %s%s", d.PresharedKey, appendOp, conf, crlf))
	}
	if d.Endpoint != "" {
		b.WriteString(fmt.Sprintf("echo Endpoint = %s %s %s%s", d.Endpoint, appendOp, conf, crlf))
	}

	// Move and install service
	b.WriteString(fmt.Sprintf("move /y %s \"c:\\program files\\wireguard\\\"%s", conf, crlf))
	b.WriteString(fmt.Sprintf("\"C:\\Program Files\\WireGuard\\wireguard.exe\" /installtunnelservice \"c:\\program files\\wireguard\\%s\"%s", conf, crlf))

	return b.String(), nil
}

// Helpers

func splitKV(line string) (key, val string, ok bool) {
	if i := strings.Index(line, "="); i > -1 {
		key = strings.TrimSpace(line[:i])
		val = strings.TrimSpace(line[i+1:])
		return key, val, true
	}
	return "", "", false
}

func splitLines(s string) []string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	return strings.Split(s, "\n")
}

func joinContinuations(lines []string) []string {
	var out []string
	var buf strings.Builder
	for _, raw := range lines {
		l := strings.TrimRight(raw, " \t")
		if strings.HasSuffix(l, "\\") {
			// remove trailing backslash; keep a space between joined parts
			l = strings.TrimSuffix(l, "\\")
			buf.WriteString(strings.TrimRight(l, " "))
			buf.WriteByte(' ')
			continue
		}
		if buf.Len() > 0 {
			buf.WriteString(strings.TrimSpace(l))
			out = append(out, buf.String())
			buf.Reset()
		} else {
			out = append(out, raw)
		}
	}
	// flush if any
	if buf.Len() > 0 {
		out = append(out, buf.String())
	}
	return out
}

func splitFieldsPreserveQuotes(s string) []string {
	var out []string
	var cur strings.Builder
	inQuote := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '"':
			inQuote = !inQuote
			cur.WriteByte(c)
		case ' ':
			if inQuote {
				cur.WriteByte(c)
			} else if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteByte(c)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

func trimQuotes(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}

func ipOnly(addr string) string {
	if i := strings.Index(addr, "/"); i > 0 {
		return addr[:i]
	}
	return addr
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

func reorderAllowedIPs(s string) string {
	parts := splitCSV(s)
	// Move /32 to the end and sort others lexicographically stable
	var cidr32 []string
	var others []string
	for _, p := range parts {
		if strings.HasSuffix(p, "/32") {
			cidr32 = append(cidr32, p)
		} else if p != "" {
			others = append(others, p)
		}
	}
	sort.Strings(others)
	res := append(others, cidr32...)
	return strings.Join(res, ",")
}

func coalesce(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
