package main

import (
	"errors"

	keyring "github.com/zalando/go-keyring"
)

const keyringService = "TunnelDeck"

type SecretStore interface {
	Get(profileID string) (string, error)
	Set(profileID, secret string) error
	Delete(profileID string) error
}

type SystemSecretStore struct{}

func (SystemSecretStore) Get(profileID string) (string, error) {
	return keyring.Get(keyringService, "profile:"+profileID)
}

func (SystemSecretStore) Set(profileID, secret string) error {
	return keyring.Set(keyringService, "profile:"+profileID, secret)
}

func (SystemSecretStore) Delete(profileID string) error {
	err := keyring.Delete(keyringService, "profile:"+profileID)
	if errors.Is(err, keyring.ErrNotFound) {
		return nil
	}
	return err
}
