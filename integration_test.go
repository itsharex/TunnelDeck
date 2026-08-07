package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

type directTCPIPRequest struct {
	DestinationAddress string
	DestinationPort    uint32
	OriginAddress      string
	OriginPort         uint32
}

func TestTunnelEndToEndWithPasswordAndHostTrust(t *testing.T) {
	target, closeTarget := startTestTarget(t)
	defer closeTarget()
	sshAddress, closeSSH := startTestSSHServer(t, "test-password")
	defer closeSSH()

	localPort := freeTCPPort(t)
	sshHost, sshPortText, err := net.SplitHostPort(sshAddress)
	if err != nil {
		t.Fatal(err)
	}
	sshPort, _ := strconv.Atoi(sshPortText)
	targetHost, targetPortText, err := net.SplitHostPort(target)
	if err != nil {
		t.Fatal(err)
	}
	targetPort, _ := strconv.Atoi(targetPortText)

	profile := validProfile()
	profile.SSHHost = sshHost
	profile.SSHPort = sshPort
	profile.LocalPort = localPort
	profile.RemoteHost = targetHost
	profile.RemotePort = targetPort
	manager := NewTunnelManager(filepath.Join(t.TempDir(), "known_hosts"), nil)

	first := manager.Start(profile, "test-password")
	if first.Code != "HOST_KEY_UNKNOWN" || first.HostKey == nil {
		t.Fatalf("first connection should require host trust, got %#v", first)
	}
	if trusted := manager.TrustHost(profile); !trusted.OK {
		t.Fatalf("TrustHost failed: %#v", trusted)
	}
	started := manager.Start(profile, "test-password")
	if !started.OK {
		t.Fatalf("Start failed after host trust: %#v", started)
	}
	defer manager.Stop(profile)

	connection, err := net.DialTimeout("tcp", profile.localEndpoint(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial local tunnel: %v", err)
	}
	defer connection.Close()
	if _, err := connection.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 4)
	if _, err := io.ReadFull(connection, response); err != nil {
		t.Fatal(err)
	}
	if string(response) != "pong" {
		t.Fatalf("tunnel response = %q, want pong", response)
	}
}

func startTestTarget(t *testing.T) (string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer connection.Close()
				request := make([]byte, 4)
				if _, err := io.ReadFull(connection, request); err == nil && string(request) == "ping" {
					_, _ = connection.Write([]byte("pong"))
				}
			}()
		}
	}()
	return listener.Addr().String(), func() {
		_ = listener.Close()
		<-done
	}
}

func startTestSSHServer(t *testing.T, password string) (string, func()) {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	config := &ssh.ServerConfig{
		PasswordCallback: func(metadata ssh.ConnMetadata, candidate []byte) (*ssh.Permissions, error) {
			if metadata.User() == "root" && string(candidate) == password {
				return nil, nil
			}
			return nil, fmt.Errorf("authentication rejected")
		},
	}
	config.AddHostKey(signer)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	var connections sync.WaitGroup
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			connections.Add(1)
			go func() {
				defer connections.Done()
				serveTestSSHConnection(connection, config)
			}()
		}
	}()
	return listener.Addr().String(), func() {
		_ = listener.Close()
		<-done
		connections.Wait()
	}
}

func serveTestSSHConnection(connection net.Conn, config *ssh.ServerConfig) {
	server, channels, requests, err := ssh.NewServerConn(connection, config)
	if err != nil {
		_ = connection.Close()
		return
	}
	defer server.Close()
	go ssh.DiscardRequests(requests)
	for request := range channels {
		if request.ChannelType() != "direct-tcpip" {
			_ = request.Reject(ssh.UnknownChannelType, "only direct-tcpip is supported")
			continue
		}
		var payload directTCPIPRequest
		if err := ssh.Unmarshal(request.ExtraData(), &payload); err != nil {
			_ = request.Reject(ssh.ConnectionFailed, "invalid forwarding request")
			continue
		}
		target := net.JoinHostPort(payload.DestinationAddress, strconv.Itoa(int(payload.DestinationPort)))
		upstream, err := net.DialTimeout("tcp", target, time.Second)
		if err != nil {
			_ = request.Reject(ssh.ConnectionFailed, err.Error())
			continue
		}
		channel, channelRequests, err := request.Accept()
		if err != nil {
			_ = upstream.Close()
			continue
		}
		go ssh.DiscardRequests(channelRequests)
		go proxyTestConnection(channel, upstream)
	}
}

func proxyTestConnection(channel ssh.Channel, upstream net.Conn) {
	defer channel.Close()
	defer upstream.Close()
	finished := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(upstream, channel)
		finished <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(channel, upstream)
		finished <- struct{}{}
	}()
	<-finished
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}
