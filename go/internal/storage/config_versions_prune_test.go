package storage

import (
	"context"
	"path/filepath"
	"testing"
)

func TestPruneConfigVersions(t *testing.T) {
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

	// Insert 10 versions.
	for i := 0; i < 10; i++ {
		if _, err := db.Exec(
			"INSERT INTO config_versions (config_json, created_at, created_by, note) VALUES (?, ?, ?, ?)",
			"{}",
			"2026-01-01T00:00:00Z",
			nil,
			"test",
		); err != nil {
			t.Fatalf("insert config_versions[%d]: %v", i, err)
		}
	}

	deleted, err := PruneConfigVersions(context.Background(), db, 3)
	if err != nil {
		t.Fatalf("PruneConfigVersions: %v", err)
	}
	if deleted != 7 {
		t.Fatalf("deleted mismatch: got %d want %d", deleted, 7)
	}

	var count int
	if err := db.QueryRow("SELECT COUNT(1) FROM config_versions").Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 3 {
		t.Fatalf("count mismatch: got %d want %d", count, 3)
	}
}

func TestPruneConfigVersions_KeepZeroNoop(t *testing.T) {
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

	for i := 0; i < 3; i++ {
		if _, err := db.Exec(
			"INSERT INTO config_versions (config_json, created_at, created_by, note) VALUES (?, ?, ?, ?)",
			"{}",
			"2026-01-01T00:00:00Z",
			nil,
			"test",
		); err != nil {
			t.Fatalf("insert config_versions[%d]: %v", i, err)
		}
	}

	deleted, err := PruneConfigVersions(context.Background(), db, 0)
	if err != nil {
		t.Fatalf("PruneConfigVersions: %v", err)
	}
	if deleted != 0 {
		t.Fatalf("deleted mismatch: got %d want %d", deleted, 0)
	}

	var count int
	if err := db.QueryRow("SELECT COUNT(1) FROM config_versions").Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 3 {
		t.Fatalf("count mismatch: got %d want %d", count, 3)
	}
}
