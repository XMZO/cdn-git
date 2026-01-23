package storage

import (
	"encoding/json"
	"errors"
	"fmt"

	"hazuki-go/internal/model"
)

func (s *ConfigStore) RotateMasterKey(currentMasterKey, newMasterKey string) error {
	s.mu.Lock()
	if !s.inited {
		s.mu.Unlock()
		return errors.New("ConfigStore not initialized")
	}
	if s.db == nil {
		s.mu.Unlock()
		return errors.New("ConfigStore missing db")
	}

	oldCrypto, err := NewCryptoContext(s.db, currentMasterKey)
	if err != nil {
		s.mu.Unlock()
		return err
	}
	newCrypto, err := NewCryptoContext(s.db, newMasterKey)
	if err != nil {
		s.mu.Unlock()
		return err
	}

	// Re-encrypt current config from the in-memory decrypted copy.
	reencryptedCurrent, err := encryptConfigSecrets(s.decrypted, newCrypto)
	if err != nil {
		s.mu.Unlock()
		return err
	}
	currentJSON, err := json.Marshal(reencryptedCurrent)
	if err != nil {
		s.mu.Unlock()
		return err
	}

	tx, err := s.db.Begin()
	if err != nil {
		s.mu.Unlock()
		return err
	}

	rollback := func(retErr error) error {
		_ = tx.Rollback()
		return retErr
	}

	if _, err := tx.Exec("UPDATE config_current SET config_json = ? WHERE id = ?", string(currentJSON), configRowID); err != nil {
		s.mu.Unlock()
		return rollback(err)
	}

	rows, err := tx.Query("SELECT id, config_json FROM config_versions")
	if err != nil {
		s.mu.Unlock()
		return rollback(err)
	}

	type rowData struct {
		id  int64
		cfg string
	}
	all := make([]rowData, 0, 64)
	for rows.Next() {
		var id int64
		var configJSON string
		if err := rows.Scan(&id, &configJSON); err != nil {
			_ = rows.Close()
			s.mu.Unlock()
			return rollback(err)
		}
		all = append(all, rowData{id: id, cfg: configJSON})
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		s.mu.Unlock()
		return rollback(err)
	}
	_ = rows.Close()

	for _, r := range all {
		var encrypted model.AppConfig
		if err := json.Unmarshal([]byte(r.cfg), &encrypted); err != nil {
			s.mu.Unlock()
			return rollback(fmt.Errorf("config_versions[%d]: json: %w", r.id, err))
		}
		decrypted, err := decryptConfigSecrets(encrypted, oldCrypto)
		if err != nil {
			s.mu.Unlock()
			return rollback(fmt.Errorf("config_versions[%d]: decrypt: %w", r.id, err))
		}
		reencrypted, err := encryptConfigSecrets(decrypted, newCrypto)
		if err != nil {
			s.mu.Unlock()
			return rollback(fmt.Errorf("config_versions[%d]: encrypt: %w", r.id, err))
		}
		encryptedJSON, err := json.Marshal(reencrypted)
		if err != nil {
			s.mu.Unlock()
			return rollback(fmt.Errorf("config_versions[%d]: marshal: %w", r.id, err))
		}
		if _, err := tx.Exec("UPDATE config_versions SET config_json = ? WHERE id = ?", string(encryptedJSON), r.id); err != nil {
			s.mu.Unlock()
			return rollback(fmt.Errorf("config_versions[%d]: update: %w", r.id, err))
		}
	}

	if err := tx.Commit(); err != nil {
		s.mu.Unlock()
		return err
	}

	s.crypto = newCrypto
	s.encrypted = reencryptedCurrent
	s.mu.Unlock()

	return nil
}
