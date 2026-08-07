package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestEncryptedPrivateKeyRequiresAndAcceptsPassphrase(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKeyWithPassphrase(privateKey, "TunnelDeck test", []byte("correct-passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	profile := validProfile()
	profile.AuthMode = AuthPrivateKey
	profile.PrivateKeyPath = path

	if _, err := authMethods(profile, ""); err == nil || !strings.Contains(err.Error(), "SECRET_REQUIRED") {
		t.Fatalf("expected SECRET_REQUIRED for encrypted key, got %v", err)
	}
	methods, err := authMethods(profile, "correct-passphrase")
	if err != nil {
		t.Fatalf("correct passphrase rejected: %v", err)
	}
	if len(methods) != 1 {
		t.Fatalf("got %d auth methods, want 1", len(methods))
	}
}

func TestTrustHostPersistsKnownHost(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "known_hosts")
	manager := NewTunnelManager(path, nil)
	profile := validProfile()
	manager.pendingHostKey[profile.ID] = pendingHostKey{
		profileID: profile.ID,
		address:   profile.sshEndpoint(),
		key:       key,
		info: HostKeyInfo{
			Host:        profile.SSHHost,
			Port:        profile.SSHPort,
			KeyType:     key.Type(),
			Fingerprint: ssh.FingerprintSHA256(key),
		},
	}
	result := manager.TrustHost(profile)
	if !result.OK {
		t.Fatalf("TrustHost failed: %s", result.Message)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Fatal("known_hosts was not written")
	}
	callback, err := manager.hostKeyCallback(profile)
	if err != nil {
		t.Fatal(err)
	}
	if err := callback(profile.sshEndpoint(), testAddr(profile.sshEndpoint()), key); err != nil {
		t.Fatalf("persisted key was not accepted: %v", err)
	}
}

type testAddr string

func (a testAddr) Network() string { return "tcp" }
func (a testAddr) String() string  { return string(a) }
