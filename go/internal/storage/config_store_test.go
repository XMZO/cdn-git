package storage

import (
	"path/filepath"
	"testing"

	"hazuki-go/internal/model"
)

func TestConfigStoreUpdate_PreserveEmptySecretsAppliedBeforeValidate(t *testing.T) {
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
	getEnv := func(string) string { return "" }
	lookupEnv := func(string) (string, bool) { return "", false }
	if err := cs.InitFromEnvironment(getEnv, lookupEnv); err != nil {
		t.Fatalf("InitFromEnvironment: %v", err)
	}

	wantToken := "oplist_token"
	wantAddr := "https://op.example.com"

	// Seed a valid enabled Sakuya config with a token.
	if err := cs.Update(UpdateRequest{
		Note: "seed",
		Updater: func(cfg model.AppConfig) (model.AppConfig, error) {
			cfg.Sakuya.Disabled = false
			cfg.Sakuya.Oplist.Disabled = false
			cfg.Sakuya.Oplist.Address = wantAddr
			cfg.Sakuya.Oplist.Token = wantToken
			return cfg, nil
		},
	}); err != nil {
		t.Fatalf("seed Update: %v", err)
	}

	// Now update while "leaving token empty" but requesting PreserveEmptySecrets.
	// This should keep the existing token and pass validation.
	if err := cs.Update(UpdateRequest{
		Note:                 "edit:sakuya:oplist",
		PreserveEmptySecrets: true,
		Updater: func(cfg model.AppConfig) (model.AppConfig, error) {
			cfg.Sakuya.Disabled = false
			cfg.Sakuya.Oplist.Disabled = false
			cfg.Sakuya.Oplist.Address = wantAddr
			cfg.Sakuya.Oplist.Token = ""
			return cfg, nil
		},
	}); err != nil {
		t.Fatalf("Update with PreserveEmptySecrets: %v", err)
	}

	got, err := cs.GetDecryptedConfig()
	if err != nil {
		t.Fatalf("GetDecryptedConfig: %v", err)
	}
	if got.Sakuya.Oplist.Token != wantToken {
		t.Fatalf("token mismatch: got %q want %q", got.Sakuya.Oplist.Token, wantToken)
	}
}
