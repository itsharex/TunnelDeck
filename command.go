package main

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/google/shlex"
)

var forwardPattern = regexp.MustCompile(`^(?:(\[[^\]]+\]|[^:]+):)?(\d+):(\[[^\]]+\]|[^:]+):(\d+)$`)

func parseSSHCommand(input string) (TunnelProfile, error) {
	tokens, err := shlex.Split(strings.TrimSpace(input))
	if err != nil {
		return TunnelProfile{}, fmt.Errorf("命令引号不完整: %w", err)
	}
	if len(tokens) < 2 || tokens[0] != "ssh" {
		return TunnelProfile{}, fmt.Errorf("请输入以 ssh 开头的命令")
	}
	profile := TunnelProfile{
		SSHPort:       22,
		LocalBind:     "127.0.0.1",
		RemoteHost:    "127.0.0.1",
		AuthMode:      AuthPassword,
		AutoReconnect: true,
	}
	var forwardSpec string
	var target string
	for index := 1; index < len(tokens); index++ {
		token := tokens[index]
		switch {
		case token == "-L" && index+1 < len(tokens):
			index++
			forwardSpec = tokens[index]
		case strings.HasPrefix(token, "-L") && len(token) > 2:
			forwardSpec = token[2:]
		case token == "-p" && index+1 < len(tokens):
			index++
			profile.SSHPort, err = strconv.Atoi(tokens[index])
			if err != nil {
				return TunnelProfile{}, fmt.Errorf("SSH 端口无效")
			}
		case token == "-i" && index+1 < len(tokens):
			index++
			profile.AuthMode = AuthPrivateKey
			profile.PrivateKeyPath = tokens[index]
		case token == "-N" || token == "-T" || token == "-n":
			continue
		case strings.HasPrefix(token, "-"):
			return TunnelProfile{}, fmt.Errorf("暂不支持参数 %s，请只保留 -L、-p、-i、-N 或 -T", token)
		default:
			if target != "" {
				return TunnelProfile{}, fmt.Errorf("不支持远程命令或多个 SSH 目标")
			}
			target = token
		}
	}
	if forwardSpec == "" {
		return TunnelProfile{}, fmt.Errorf("命令中缺少 -L 本地转发参数")
	}
	matches := forwardPattern.FindStringSubmatch(forwardSpec)
	if matches == nil {
		return TunnelProfile{}, fmt.Errorf("-L 格式应为 [绑定地址:]本地端口:远程主机:远程端口")
	}
	if matches[1] != "" {
		profile.LocalBind = trimIPv6Brackets(matches[1])
	}
	profile.LocalPort, _ = strconv.Atoi(matches[2])
	profile.RemoteHost = trimIPv6Brackets(matches[3])
	profile.RemotePort, _ = strconv.Atoi(matches[4])
	parts := strings.SplitN(target, "@", 2)
	if len(parts) != 2 {
		return TunnelProfile{}, fmt.Errorf("SSH 目标应为 用户名@主机")
	}
	profile.Username = parts[0]
	profile.SSHHost = trimIPv6Brackets(parts[1])
	profile.Name = fmt.Sprintf("%s · %d→%d", profile.SSHHost, profile.LocalPort, profile.RemotePort)
	if err := validateProfile(profile); err != nil {
		return TunnelProfile{}, err
	}
	return profile, nil
}

func buildSSHCommand(profile TunnelProfile) string {
	profile.applyDefaults()
	parts := []string{
		"ssh",
		"-N",
		"-L",
		fmt.Sprintf("%s:%d:%s:%d", formatCommandHost(profile.LocalBind), profile.LocalPort, formatCommandHost(profile.RemoteHost), profile.RemotePort),
		"-p",
		strconv.Itoa(profile.SSHPort),
	}
	if profile.AuthMode == AuthPrivateKey && profile.PrivateKeyPath != "" {
		parts = append(parts, "-i", shellQuote(profile.PrivateKeyPath))
	}
	parts = append(parts, fmt.Sprintf("%s@%s", profile.Username, formatCommandHost(profile.SSHHost)))
	return strings.Join(parts, " ")
}

func trimIPv6Brackets(value string) string {
	return strings.TrimSuffix(strings.TrimPrefix(value, "["), "]")
}

func formatCommandHost(value string) string {
	if strings.Contains(value, ":") && !strings.HasPrefix(value, "[") {
		return "[" + value + "]"
	}
	return value
}

func shellQuote(value string) string {
	if !strings.ContainsAny(value, " \t'\"") {
		return value
	}
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}
