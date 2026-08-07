package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

type configFile struct {
	Version  int             `json:"version"`
	Profiles []TunnelProfile `json:"profiles"`
}

type ConfigStore struct {
	dir            string
	configPath     string
	knownHostsPath string
}

func NewConfigStore() (*ConfigStore, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return nil, fmt.Errorf("读取系统配置目录失败: %w", err)
	}
	dir := filepath.Join(base, "TunnelDeck")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("创建配置目录失败: %w", err)
	}
	return &ConfigStore{
		dir:            dir,
		configPath:     filepath.Join(dir, "profiles.json"),
		knownHostsPath: filepath.Join(dir, "known_hosts"),
	}, nil
}

func (s *ConfigStore) Load() ([]TunnelProfile, error) {
	data, err := os.ReadFile(s.configPath)
	if errors.Is(err, os.ErrNotExist) {
		return []TunnelProfile{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("读取配置失败: %w", err)
	}
	var config configFile
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("配置文件格式错误: %w", err)
	}
	for index := range config.Profiles {
		config.Profiles[index].applyDefaults()
	}
	return config.Profiles, nil
}

func (s *ConfigStore) Save(profiles []TunnelProfile) error {
	data, err := json.MarshalIndent(configFile{Version: 1, Profiles: profiles}, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化配置失败: %w", err)
	}
	temp, err := os.CreateTemp(s.dir, "profiles-*.tmp")
	if err != nil {
		return fmt.Errorf("创建临时配置失败: %w", err)
	}
	tempName := temp.Name()
	defer os.Remove(tempName)
	if err := temp.Chmod(0o600); err != nil {
		temp.Close()
		return err
	}
	if _, err := temp.Write(append(data, '\n')); err != nil {
		temp.Close()
		return fmt.Errorf("写入配置失败: %w", err)
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempName, s.configPath); err != nil {
		return fmt.Errorf("替换配置失败: %w", err)
	}
	return nil
}

func newProfileID() (string, error) {
	buffer := make([]byte, 12)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return hex.EncodeToString(buffer), nil
}
