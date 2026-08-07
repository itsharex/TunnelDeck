package main

import (
	"strings"
	"testing"
)

func TestParseSSHCommandExample(t *testing.T) {
	profile, err := parseSSHCommand("ssh -L 9108:127.0.0.1:9108 -p 33899 root@ssh.example.com")
	if err != nil {
		t.Fatalf("parseSSHCommand returned error: %v", err)
	}
	if profile.SSHHost != "ssh.example.com" || profile.SSHPort != 33899 || profile.Username != "root" {
		t.Fatalf("unexpected SSH target: %#v", profile)
	}
	if profile.LocalBind != "127.0.0.1" || profile.LocalPort != 9108 {
		t.Fatalf("unexpected local endpoint: %#v", profile)
	}
	if profile.RemoteHost != "127.0.0.1" || profile.RemotePort != 9108 {
		t.Fatalf("unexpected remote endpoint: %#v", profile)
	}
	if got := buildSSHCommand(profile); got != "ssh -N -L 127.0.0.1:9108:127.0.0.1:9108 -p 33899 root@ssh.example.com" {
		t.Fatalf("unexpected equivalent command: %s", got)
	}
}

func TestParseSSHCommandPrivateKeyAndIPv6(t *testing.T) {
	profile, err := parseSSHCommand("ssh -N -L [::1]:8080:[2001:db8::2]:80 -i '/tmp/my key' user@[2001:db8::1]")
	if err != nil {
		t.Fatalf("parseSSHCommand returned error: %v", err)
	}
	if profile.AuthMode != AuthPrivateKey || profile.PrivateKeyPath != "/tmp/my key" {
		t.Fatalf("unexpected private key settings: %#v", profile)
	}
	if profile.LocalBind != "::1" || profile.RemoteHost != "2001:db8::2" || profile.SSHHost != "2001:db8::1" {
		t.Fatalf("unexpected IPv6 settings: %#v", profile)
	}
	command := buildSSHCommand(profile)
	if !strings.Contains(command, "-i '/tmp/my key'") || !strings.Contains(command, "user@[2001:db8::1]") {
		t.Fatalf("unexpected command: %s", command)
	}
}

func TestParseSSHCommandRejectsExtraCapabilities(t *testing.T) {
	inputs := []string{
		"ssh -R 9000:127.0.0.1:9000 root@example.com",
		"ssh -L 9000:127.0.0.1:9000 root@example.com uptime",
		"ssh -L 9000:127.0.0.1:9000 -o ProxyCommand=bad root@example.com",
	}
	for _, input := range inputs {
		if _, err := parseSSHCommand(input); err == nil {
			t.Fatalf("expected rejection for %q", input)
		}
	}
}
