package secret

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

const (
	fingerprintLength = 16
	fullFingerprint   = sha256.Size * 2
	maxVisible        = 4
	minRedactable     = 8
	redactedFully     = "[redacted]"
)

func Redact(value string) string {
	if len(value) < minRedactable {
		return redactedFully
	}
	visible := min(len(value)/4, maxVisible)
	return value[:visible] + "..." + value[len(value)-visible:]
}

func FullFingerprint(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func Fingerprint(value string) string {
	return FullFingerprint(value)[:fingerprintLength]
}

func NormalizeFingerprint(value string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(value))
	if len(normalized) != fingerprintLength && len(normalized) != fullFingerprint {
		return "", fmt.Errorf("fingerprint must be %d or %d hex characters, got %d", fingerprintLength, fullFingerprint, len(normalized))
	}
	if _, err := hex.DecodeString(normalized); err != nil {
		return "", fmt.Errorf("fingerprint is not hexadecimal: %w", err)
	}
	return normalized[:fingerprintLength], nil
}
