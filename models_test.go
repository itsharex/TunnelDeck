package main

import (
	"strings"
	"testing"
)

func validProfile() TunnelProfile {
	return TunnelProfile{
		ID:            "test-profile",
		Name:          "Local web",
		SSHHost:       "ssh.example.com",
		SSHPort:       22,
		Username:      "root",
		LocalBind:     "127.0.0.1",
		LocalPort:     9108,
		RemoteHost:    "127.0.0.1",
		RemotePort:    9108,
		AuthMode:      AuthPassword,
		AutoReconnect: true,
	}
}

func TestValidateProfile(t *testing.T) {
	profile := validProfile()
	if err := validateProfile(profile); err != nil {
		t.Fatalf("valid profile rejected: %v", err)
	}
	profile.LocalBind = "0.0.0.0"
	if err := validateProfile(profile); err != nil {
		t.Fatalf("explicit broad bind should remain supported: %v", err)
	}
	profile.SSHHost = "host; command"
	if err := validateProfile(profile); err == nil {
		t.Fatal("host with whitespace should be rejected")
	}
}

func TestFriendlySSHErrorDoesNotEchoSecretMarker(t *testing.T) {
	message := friendlySSHError(assertError("SECRET_REQUIRED: 请输入 SSH 密码"))
	if strings.Contains(message, "SECRET_REQUIRED") || message != "请输入 SSH 密码" {
		t.Fatalf("unexpected friendly error: %q", message)
	}
}

type assertError string

func (e assertError) Error() string { return string(e) }
