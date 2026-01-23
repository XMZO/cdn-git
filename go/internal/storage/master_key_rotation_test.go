package storage

import (
	"path/filepath"
	"testing"

	"hazuki-go/internal/model"
)

func TestRotateMasterKey_ReencryptsVersionsAndCurrent(t *testing.T) {
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

	oldKey := "old-master-key"
	oldCrypto, err := NewCryptoContext(db, oldKey)
	if err != nil {
		t.Fatalf("NewCryptoContext(old): %v", err)
	}

	cs := NewConfigStore(db, oldCrypto)
	getEnv := func(string) string { return "" }
	lookupEnv := func(string) (string, bool) { return "", false }
	if err := cs.InitFromEnvironment(getEnv, lookupEnv); err != nil {
		t.Fatalf("InitFromEnvironment: %v", err)
	}

	wantToken := "ghp_test_secret"
	wantWorker := "worker_secret"
	if err := cs.Update(UpdateRequest{
		Note: "test",
		Updater: func(cfg model.AppConfig) (model.AppConfig, error) {
			cfg.Git.GithubToken = wantToken
			cfg.Torcherino.WorkerSecretKey = wantWorker
			return cfg, nil
		},
	}); err != nil {
		t.Fatalf("Update: %v", err)
	}

	versions, err := cs.ListVersions(20)
	if err != nil {
		t.Fatalf("ListVersions: %v", err)
	}
	if len(versions) == 0 {
		t.Fatalf("expected versions")
	}
	versionID := versions[0].ID

	newKey := "new-master-key"
	if err := cs.RotateMasterKey(oldKey, newKey); err != nil {
		t.Fatalf("RotateMasterKey: %v", err)
	}

	newCrypto, err := NewCryptoContext(db, newKey)
	if err != nil {
		t.Fatalf("NewCryptoContext(new): %v", err)
	}
	cs2 := NewConfigStore(db, newCrypto)
	if err := cs2.InitFromEnvironment(getEnv, lookupEnv); err != nil {
		t.Fatalf("InitFromEnvironment(after rotate): %v", err)
	}

	cfg, err := cs2.GetDecryptedConfig()
	if err != nil {
		t.Fatalf("GetDecryptedConfig: %v", err)
	}
	if cfg.Git.GithubToken != wantToken {
		t.Fatalf("github token mismatch: got %q want %q", cfg.Git.GithubToken, wantToken)
	}
	if cfg.Torcherino.WorkerSecretKey != wantWorker {
		t.Fatalf("worker secret mismatch: got %q want %q", cfg.Torcherino.WorkerSecretKey, wantWorker)
	}

	if err := cs2.RestoreVersion(versionID, nil); err != nil {
		t.Fatalf("RestoreVersion(after rotate): %v", err)
	}
}
