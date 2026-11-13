package secret

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"slices"
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

const (
	AlgoSHA256 = "sha256"
	AlgoSHA1   = "sha1"
	AlgoSHA512 = "sha512"
)

var algorithms = []string{AlgoSHA256, AlgoSHA1, AlgoSHA512}

func Algorithms() []string {
	return append([]string(nil), algorithms...)
}

func Digests(value string) map[string]string {
	data := []byte(value)
	sha256Sum := sha256.Sum256(data)
	sha1Sum := sha1.Sum(data)
	sha512Sum := sha512.Sum512(data)
	return map[string]string{
		AlgoSHA256: hex.EncodeToString(sha256Sum[:]),
		AlgoSHA1:   hex.EncodeToString(sha1Sum[:]),
		AlgoSHA512: hex.EncodeToString(sha512Sum[:]),
	}
}

func NormalizeDigest(algorithm, value string) (string, error) {
	if algorithm == AlgoSHA256 {
		return NormalizeFingerprint(value)
	}
	if !slices.Contains(algorithms, algorithm) {
		return "", fmt.Errorf("unknown fingerprint algorithm %q: want %s", algorithm, strings.Join(algorithms, ", "))
	}
	normalized := strings.ToLower(strings.TrimSpace(value))
	if len(normalized) < fingerprintLength {
		return "", fmt.Errorf("fingerprint must have at least %d hex characters, got %d", fingerprintLength, len(normalized))
	}
	if _, err := hex.DecodeString(normalized); err != nil {
		return "", fmt.Errorf("fingerprint is not hexadecimal: %w", err)
	}
	return normalized, nil
}
