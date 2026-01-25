package storage

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"hazuki-go/internal/model"
)

func TestConfigStore_ConfigJSONStoredEncryptedWhenMasterKeySet(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "hazuki.db")

	db, err := OpenDB(dbPath)
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	if err := Migrate(db); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	crypto, err := NewCryptoContext(db, "test-master-key")
	if err != nil {
		t.Fatalf("NewCryptoContext: %v", err)
	}
	cs := NewConfigStore(db, crypto)
	if err := cs.InitFromEnvironment(func(string) string { return "" }, func(string) (string, bool) { return "", false }); err != nil {
		t.Fatalf("InitFromEnvironment: %v", err)
	}

	var stored string
	if err := db.QueryRow("SELECT config_json FROM config_current WHERE id = 1;").Scan(&stored); err != nil {
		t.Fatalf("query config_current: %v", err)
	}
	if !strings.HasPrefix(strings.TrimSpace(stored), encPrefix) {
		t.Fatalf("expected config_json to be encrypted, got %q", stored)
	}

	plain, err := crypto.DecryptString(stored)
	if err != nil {
		t.Fatalf("DecryptString(config_json): %v", err)
	}

	var cfg model.AppConfig
	if err := json.Unmarshal([]byte(plain), &cfg); err != nil {
		t.Fatalf("unmarshal decrypted config_json: %v", err)
	}
}

func TestConfigStore_ReloadFromDB_UpgradesPlaintextConfigToEncrypted(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "hazuki.db")

	db, err := OpenDB(dbPath)
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	if err := Migrate(db); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	cryptoOff, err := NewCryptoContext(db, "")
	if err != nil {
		t.Fatalf("NewCryptoContext(empty): %v", err)
	}
	cs := NewConfigStore(db, cryptoOff)
	if err := cs.InitFromEnvironment(func(string) string { return "" }, func(string) (string, bool) { return "", false }); err != nil {
		t.Fatalf("InitFromEnvironment: %v", err)
	}

	var stored string
	if err := db.QueryRow("SELECT config_json FROM config_current WHERE id = 1;").Scan(&stored); err != nil {
		t.Fatalf("query config_current: %v", err)
	}
	if strings.HasPrefix(strings.TrimSpace(stored), encPrefix) {
		t.Fatalf("expected plaintext config_json before upgrade, got %q", stored)
	}

	cryptoOn, err := NewCryptoContext(db, "new-master-key")
	if err != nil {
		t.Fatalf("NewCryptoContext: %v", err)
	}
	if err := cs.ReloadFromDB(cryptoOn); err != nil {
		t.Fatalf("ReloadFromDB: %v", err)
	}

	if err := db.QueryRow("SELECT config_json FROM config_current WHERE id = 1;").Scan(&stored); err != nil {
		t.Fatalf("query upgraded config_current: %v", err)
	}
	if !strings.HasPrefix(strings.TrimSpace(stored), encPrefix) {
		t.Fatalf("expected encrypted config_json after upgrade, got %q", stored)
	}

	plain, err := cryptoOn.DecryptString(stored)
	if err != nil {
		t.Fatalf("DecryptString(config_json): %v", err)
	}
	var cfg model.AppConfig
	if err := json.Unmarshal([]byte(plain), &cfg); err != nil {
		t.Fatalf("unmarshal upgraded config_json: %v", err)
	}

	var ver string
	if err := db.QueryRow("SELECT config_json FROM config_versions ORDER BY id DESC LIMIT 1;").Scan(&ver); err != nil {
		t.Fatalf("query config_versions: %v", err)
	}
	if !strings.HasPrefix(strings.TrimSpace(ver), encPrefix) {
		t.Fatalf("expected encrypted config_versions row after upgrade, got %q", ver)
	}
}

func TestConfigStore_RotateMasterKey_ReencryptsWholeConfigAndSecrets(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "hazuki.db")

	db, err := OpenDB(dbPath)
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	if err := Migrate(db); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	oldCrypto, err := NewCryptoContext(db, "old-master-key")
	if err != nil {
		t.Fatalf("NewCryptoContext(old): %v", err)
	}

	cs := NewConfigStore(db, oldCrypto)
	if err := cs.InitFromEnvironment(func(string) string { return "" }, func(string) (string, bool) { return "", false }); err != nil {
		t.Fatalf("InitFromEnvironment: %v", err)
	}

	// Seed a secret to ensure inner secret re-encryption is exercised.
	if err := cs.Update(UpdateRequest{
		Note: "seed",
		Updater: func(cfg model.AppConfig) (model.AppConfig, error) {
			cfg.Sakuya.Disabled = false
			cfg.Sakuya.Oplist.Disabled = false
			cfg.Sakuya.Oplist.Address = "https://op.example.com"
			cfg.Sakuya.Oplist.Token = "tok"
			cfg.Sakuya.Instances = []model.SakuyaOplistInstance{
				{
					ID:       "i1",
					Prefix:   "op1",
					Disabled: false,
					Address:  "https://op2.example.com",
					Token:    "tok2",
				},
			}
			return cfg, nil
		},
	}); err != nil {
		t.Fatalf("Update: %v", err)
	}

	if err := cs.RotateMasterKey("old-master-key", "new-master-key"); err != nil {
		t.Fatalf("RotateMasterKey: %v", err)
	}

	newCrypto, err := NewCryptoContext(db, "new-master-key")
	if err != nil {
		t.Fatalf("NewCryptoContext(new): %v", err)
	}

	var stored string
	if err := db.QueryRow("SELECT config_json FROM config_current WHERE id = 1;").Scan(&stored); err != nil {
		t.Fatalf("query config_current: %v", err)
	}
	if _, err := oldCrypto.DecryptString(stored); err == nil {
		t.Fatalf("expected old master key to fail decrypting current config_json")
	} else if !errors.Is(err, ErrDecryptAuthFailed) && !strings.Contains(strings.ToLower(err.Error()), "decrypt") {
		t.Fatalf("expected decrypt auth failure, got: %v", err)
	}

	plain, err := newCrypto.DecryptString(stored)
	if err != nil {
		t.Fatalf("DecryptString(config_json) with new key: %v", err)
	}
	var encCfg model.AppConfig
	if err := json.Unmarshal([]byte(plain), &encCfg); err != nil {
		t.Fatalf("unmarshal config_json: %v", err)
	}

	// Inner secret should also be re-encrypted with the new key.
	if got, err := newCrypto.DecryptString(encCfg.Sakuya.Oplist.Token); err != nil || got != "tok" {
		t.Fatalf("new key decrypt token: got=%q err=%v", got, err)
	}
	if _, err := oldCrypto.DecryptString(encCfg.Sakuya.Oplist.Token); err == nil {
		t.Fatalf("expected old key to fail decrypting token")
	}

	if len(encCfg.Sakuya.Instances) != 1 {
		t.Fatalf("expected 1 instance, got %d", len(encCfg.Sakuya.Instances))
	}
	if got, err := newCrypto.DecryptString(encCfg.Sakuya.Instances[0].Token); err != nil || got != "tok2" {
		t.Fatalf("new key decrypt instance token: got=%q err=%v", got, err)
	}
	if _, err := oldCrypto.DecryptString(encCfg.Sakuya.Instances[0].Token); err == nil {
		t.Fatalf("expected old key to fail decrypting instance token")
	}
}
