package main

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestEncryptedStoreHidesDeviceTokenAndRejectsWrongKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "relay-state")
	key := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x12}, 32))
	store, err := openEncryptedStore(path, time.Now, key, "staging")
	if err != nil {
		t.Fatal(err)
	}
	token := "test-provider-token-local-fixture"
	inst, err := store.RegisterInstallation(InstallRequest{Provider: "fcm", Environment: "staging", Token: token})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.RegisterInstallation(InstallRequest{Provider: "fcm", Environment: "production", Token: "another-fixture-token"}); err == nil {
		t.Fatal("real staging mode accepted a production installation")
	}
	onDisk, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(onDisk, []byte(token)) || !bytes.HasPrefix(onDisk, []byte(encryptedStatePrefix)) {
		t.Fatal("state was written without encryption")
	}
	store, err = openEncryptedStore(path, time.Now, key, "staging")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateToken(inst.InstallationID, inst.InstallationCredential, TokenRequest{Token: token}); err != nil {
		t.Fatal(err)
	}
	wrongKey := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x31}, 32))
	if _, err := openEncryptedStore(path, time.Now, wrongKey, "staging"); err == nil {
		t.Fatal("encrypted state opened with wrong key")
	}
	if _, err := OpenStore(path, time.Now); err == nil {
		t.Fatal("simulation opened encrypted state")
	}
}

func TestEncryptedStoreRefusesExistingPlaintextState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "relay-state")
	if _, err := OpenStore(path, time.Now); err != nil {
		t.Fatal(err)
	}
	key := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x12}, 32))
	if _, err := openEncryptedStore(path, time.Now, key, "staging"); err == nil {
		t.Fatal("real provider mode accepted the simulation state")
	}
}

func TestProductionStateIsEncryptedAndSeparateFromStaging(t *testing.T) {
	dir := t.TempDir()
	production := filepath.Join(dir, "production-state")
	staging := filepath.Join(dir, "staging-state")
	key := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x23}, 32))
	store, err := openEncryptedStore(production, time.Now, key, "production")
	if err != nil {
		t.Fatal(err)
	}
	// Real-provider modes check token shape: APNs hex, FCM registration IDs.
	tokens := map[string]string{
		"apns": strings.Repeat("ab", 32),
		"fcm":  "fixture-production-token:" + strings.Repeat("Q", 32),
	}
	for _, provider := range []string{"apns", "fcm"} {
		for _, mode := range []string{"staging", "production"} {
			env := providerEnvironment(mode, provider)
			_, err := store.RegisterInstallation(InstallRequest{Provider: provider, Environment: env, Token: tokens[provider]})
			if (err == nil) != (mode == "production") {
				t.Fatalf("register %s/%s: %v", provider, env, err)
			}
		}
	}
	raw, err := os.ReadFile(production)
	if err != nil || !bytes.HasPrefix(raw, []byte(productionStatePrefix)) || bytes.Contains(raw, []byte("fixture-production-token")) ||
		bytes.Contains(raw, []byte(tokens["apns"])) {
		t.Fatal("production state is not encrypted with its own format")
	}
	if _, err := openEncryptedStore(production, time.Now, key, "production"); err != nil {
		t.Fatal(err)
	}
	if _, err := openEncryptedStore(staging, time.Now, key, "staging"); err != nil {
		t.Fatal(err)
	}
	if _, err := openEncryptedStore(production, time.Now, key, "staging"); err == nil {
		t.Fatal("staging reopened production state")
	}
	if _, err := openEncryptedStore(staging, time.Now, key, "production"); err == nil {
		t.Fatal("production reopened staging state")
	}
}
