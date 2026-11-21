package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"time"
)

const (
	encryptedStatePrefix  = "nodescope-relay-gcm-v1\n"
	productionStatePrefix = "nodescope-relay-production-gcm-v1\n"
)

func openEncryptedStore(path string, now func() time.Time, rawKey, mode string) (*Store, error) {
	key, err := base64.RawURLEncoding.DecodeString(rawKey)
	if err != nil || len(key) != 32 {
		return nil, errors.New("RELAY_STATE_KEY must be an unpadded base64url key of exactly 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, err
	}
	return openStore(path, now, aead, mode)
}

func decryptRelayState(aead cipher.AEAD, raw, prefix []byte) ([]byte, error) {
	if !bytes.HasPrefix(raw, prefix) {
		return nil, errors.New("expected encrypted relay state")
	}
	return aead.Open(nil, nil, raw[len(prefix):], prefix)
}
