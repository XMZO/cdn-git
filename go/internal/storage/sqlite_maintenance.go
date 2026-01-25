package storage

import (
	"context"
	"database/sql"
)

type SQLiteStats struct {
	PageSize      int64
	PageCount     int64
	FreelistCount int64
}

func (s SQLiteStats) TotalBytes() int64 {
	if s.PageSize <= 0 || s.PageCount <= 0 {
		return 0
	}
	return s.PageSize * s.PageCount
}

func (s SQLiteStats) FreeBytes() int64 {
	if s.PageSize <= 0 || s.FreelistCount <= 0 {
		return 0
	}
	return s.PageSize * s.FreelistCount
}

func ReadSQLiteStats(ctx context.Context, db *sql.DB) (SQLiteStats, error) {
	if db == nil {
		return SQLiteStats{}, nil
	}

	var st SQLiteStats
	if err := db.QueryRowContext(ctx, "PRAGMA page_size;").Scan(&st.PageSize); err != nil {
		return SQLiteStats{}, err
	}
	if err := db.QueryRowContext(ctx, "PRAGMA page_count;").Scan(&st.PageCount); err != nil {
		return SQLiteStats{}, err
	}
	if err := db.QueryRowContext(ctx, "PRAGMA freelist_count;").Scan(&st.FreelistCount); err != nil {
		return SQLiteStats{}, err
	}
	return st, nil
}

func Vacuum(ctx context.Context, db *sql.DB) error {
	if db == nil {
		return nil
	}
	_, err := db.ExecContext(ctx, "VACUUM;")
	return err
}

func OptimizeSQLite(ctx context.Context, db *sql.DB) error {
	if db == nil {
		return nil
	}
	_, err := db.ExecContext(ctx, "PRAGMA optimize;")
	return err
}
