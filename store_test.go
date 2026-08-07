package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestConfigStoreRoundTripDoesNotContainSecrets(t *testing.T) {
	dir := t.TempDir()
	store := &ConfigStore{
		dir:            dir,
		configPath:     filepath.Join(dir, "profiles.json"),
		knownHostsPath: filepath.Join(dir, "known_hosts"),
	}
	profile := validProfile()
	profile.RememberSecret = true
	if err := store.Save([]TunnelProfile{profile}); err != nil {
		t.Fatalf("Save returned error: %v", err)
	}
	data, err := os.ReadFile(store.configPath)
	if err != nil {
		t.Fatalf("ReadFile returned error: %v", err)
	}
	if strings.Contains(string(data), "top-secret") {
		t.Fatalf("configuration appears to contain a credential field: %s", data)
	}
	var document map[string]any
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	profilesValue := document["profiles"].([]any)
	profileValue := profilesValue[0].(map[string]any)
	for _, forbidden := range []string{"secret", "password", "passphrase"} {
		if _, exists := profileValue[forbidden]; exists {
			t.Fatalf("configuration contains forbidden key %q", forbidden)
		}
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if len(loaded) != 1 || loaded[0].SSHHost != profile.SSHHost {
		t.Fatalf("unexpected round trip: %#v", loaded)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(store.configPath)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != 0o600 {
			t.Fatalf("config permissions = %o, want 600", got)
		}
	}
}
