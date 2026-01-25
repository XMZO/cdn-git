package storage

import (
	"context"
	"database/sql"
	"errors"
)

// PruneConfigVersions keeps only the newest "keep" rows in config_versions by id,
// deleting older ones. A keep value <= 0 means "no pruning".
//
// This is intended to prevent unbounded DB growth from frequent config saves.
func PruneConfigVersions(ctx context.Context, db *sql.DB, keep int) (deleted int64, err error) {
	if db == nil || keep <= 0 {
		return 0, nil
	}

	var cutoffID int64
	// Find the Nth newest id (0-based offset).
	row := db.QueryRowContext(ctx, "SELECT id FROM config_versions ORDER BY id DESC LIMIT 1 OFFSET ?;", keep-1)
	if err := row.Scan(&cutoffID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, nil
		}
		return 0, err
	}

	res, err := db.ExecContext(ctx, "DELETE FROM config_versions WHERE id < ?;", cutoffID)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}
