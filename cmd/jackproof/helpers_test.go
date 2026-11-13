package main

import "github.com/ryankshah/jackproof/internal/secret"

func secretFingerprint(key string) string {
	return secret.FullFingerprint(key)
}
