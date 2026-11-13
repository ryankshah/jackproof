package hunt

import (
	"bytes"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strings"
)

const (
	ClassHosting   = "hosting"
	ClassCorporate = "corporate"
)

type Network struct {
	Prefix netip.Prefix
	ASN    string
	Org    string
	Class  string
}

type Networks struct {
	entries []Network
}

func NewNetworks(known []string) (*Networks, error) {
	networks := &Networks{}
	for _, cidr := range known {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(cidr))
		if err != nil {
			return nil, fmt.Errorf("known network %q: %w", cidr, err)
		}
		networks.entries = append(networks.entries, Network{Prefix: prefix.Masked(), Class: ClassCorporate})
	}
	return networks, nil
}

func (n *Networks) LoadMap(data []byte) error {
	reader := csv.NewReader(bytes.NewReader(data))
	reader.FieldsPerRecord = -1
	reader.Comment = '#'
	for line := 1; ; line++ {
		record, err := reader.Read()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read network map line %d: %w", line, err)
		}
		if len(record) < 4 {
			return fmt.Errorf("network map line %d needs cidr, asn, org and class", line)
		}
		prefix, err := netip.ParsePrefix(strings.TrimSpace(record[0]))
		if err != nil {
			if line == 1 {
				continue
			}
			return fmt.Errorf("network map line %d: %w", line, err)
		}
		n.entries = append(n.entries, Network{
			Prefix: prefix.Masked(), ASN: strings.TrimSpace(record[1]), Org: strings.TrimSpace(record[2]), Class: strings.ToLower(strings.TrimSpace(record[3])),
		})
	}
}

func (n *Networks) Lookup(address string) (Network, bool) {
	if n == nil {
		return Network{}, false
	}
	parsed, err := netip.ParseAddr(address)
	if err != nil {
		return Network{}, false
	}
	var best Network
	found := false
	for _, entry := range n.entries {
		if entry.Prefix.Contains(parsed) && (!found || entry.Prefix.Bits() > best.Prefix.Bits()) {
			best, found = entry, true
		}
	}
	return best, found
}

func (n *Networks) Configured() bool {
	return n != nil && len(n.entries) > 0
}

func networkOf(address string) (string, bool) {
	parsed, err := netip.ParseAddr(address)
	if err != nil || parsed.IsLoopback() || parsed.IsPrivate() || parsed.IsUnspecified() {
		return "", false
	}
	bits := 24
	if parsed.Is6() {
		bits = 48
	}
	prefix, err := parsed.Prefix(bits)
	if err != nil {
		return "", false
	}
	return prefix.String(), true
}
