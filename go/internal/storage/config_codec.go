package storage

import (
	"encoding/json"
	"errors"
	"strings"

	"hazuki-go/internal/model"
)

func decodeConfigRow(value string, crypto *CryptoContext) (model.AppConfig, error) {
	raw := strings.TrimSpace(value)
	if raw == "" {
		return model.AppConfig{}, errors.New("config json is empty")
	}

	if crypto == nil {
		if strings.HasPrefix(raw, encPrefix) {
			return model.AppConfig{}, errors.New("HAZUKI_MASTER_KEY is required to decrypt config")
		}
	} else {
		dec, err := crypto.DecryptString(raw)
		if err != nil {
			return model.AppConfig{}, err
		}
		raw = dec
	}

	var cfg model.AppConfig
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return model.AppConfig{}, err
	}
	return cfg, nil
}

func encodeConfigRow(cfg model.AppConfig, crypto *CryptoContext) (string, error) {
	b, err := json.Marshal(cfg)
	if err != nil {
		return "", err
	}
	raw := string(b)
	if crypto != nil {
		return crypto.EncryptString(raw)
	}
	return raw, nil
}

