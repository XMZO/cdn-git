package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

type TrafficCounts struct {
	BytesIn  int64 `json:"bytesIn"`
	BytesOut int64 `json:"bytesOut"`
	Requests int64 `json:"requests"`
}

type TrafficDelta struct {
	Service string
	TrafficCounts
}

type TrafficRetention struct {
	HourDays    int
	DayDays     int
	MonthMonths int
	YearYears   int
}

type TrafficServiceSelector struct {
	Mode    string // total | exact | prefix
	Service string // exact or prefix root
}

type TrafficSeriesPoint struct {
	StartTS int64 `json:"startTs"`
	TrafficCounts
}

const (
	trafficBucketHour  = "hour"
	trafficBucketDay   = "day"
	trafficBucketMonth = "month"
	trafficBucketYear  = "year"

	metaKeyTrafficRetentionHourDays    = "traffic_retention_hour_days"
	metaKeyTrafficRetentionDayDays     = "traffic_retention_day_days"
	metaKeyTrafficRetentionMonthMonths = "traffic_retention_month_months"
	metaKeyTrafficRetentionYearYears   = "traffic_retention_year_years"
)

func DefaultTrafficRetention() TrafficRetention {
	return TrafficRetention{
		HourDays:    7,
		DayDays:     180,
		MonthMonths: 36,
		YearYears:   10,
	}
}

func AddTrafficTotals(ctx context.Context, db *sql.DB, deltas []TrafficDelta, now time.Time) error {
	if db == nil {
		return errors.New("db is nil")
	}
	if len(deltas) == 0 {
		return nil
	}
	now = now.UTC()
	ts := now.Format(time.RFC3339Nano)

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.PrepareContext(ctx, `
INSERT INTO traffic_totals (service, bytes_in, bytes_out, requests, updated_at)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT(service) DO UPDATE SET
  bytes_in = bytes_in + excluded.bytes_in,
  bytes_out = bytes_out + excluded.bytes_out,
  requests = requests + excluded.requests,
  updated_at = excluded.updated_at;
`)
	if err != nil {
		return err
	}
	defer func() { _ = stmt.Close() }()

	for _, d := range deltas {
		svc := strings.TrimSpace(d.Service)
		if svc == "" {
			continue
		}
		if d.BytesIn == 0 && d.BytesOut == 0 && d.Requests == 0 {
			continue
		}
		if _, err := stmt.ExecContext(ctx, svc, d.BytesIn, d.BytesOut, d.Requests, ts); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func AddTrafficBucket(ctx context.Context, db *sql.DB, kind string, startTS int64, deltas []TrafficDelta, now time.Time) error {
	if db == nil {
		return errors.New("db is nil")
	}
	if len(deltas) == 0 {
		return nil
	}
	if kind != trafficBucketHour && kind != trafficBucketDay && kind != trafficBucketMonth && kind != trafficBucketYear {
		return fmt.Errorf("invalid traffic bucket kind: %q", kind)
	}
	if startTS <= 0 {
		return errors.New("startTS must be > 0")
	}
	now = now.UTC()
	ts := now.Format(time.RFC3339Nano)

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.PrepareContext(ctx, `
INSERT INTO traffic_buckets (kind, start_ts, service, bytes_in, bytes_out, requests, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(kind, start_ts, service) DO UPDATE SET
  bytes_in = bytes_in + excluded.bytes_in,
  bytes_out = bytes_out + excluded.bytes_out,
  requests = requests + excluded.requests,
  updated_at = excluded.updated_at;
`)
	if err != nil {
		return err
	}
	defer func() { _ = stmt.Close() }()

	for _, d := range deltas {
		svc := strings.TrimSpace(d.Service)
		if svc == "" {
			continue
		}
		if d.BytesIn == 0 && d.BytesOut == 0 && d.Requests == 0 {
			continue
		}
		if _, err := stmt.ExecContext(ctx, kind, startTS, svc, d.BytesIn, d.BytesOut, d.Requests, ts); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func AddTrafficSample(ctx context.Context, db *sql.DB, bucketStartTS map[string]int64, deltas []TrafficDelta, now time.Time) error {
	if db == nil {
		return errors.New("db is nil")
	}
	if len(deltas) == 0 {
		return nil
	}
	now = now.UTC()
	ts := now.Format(time.RFC3339Nano)

	buckets := map[string]int64{}
	for kind, startTS := range bucketStartTS {
		if startTS <= 0 {
			continue
		}
		switch kind {
		case trafficBucketHour, trafficBucketDay, trafficBucketMonth, trafficBucketYear:
			buckets[kind] = startTS
		}
	}
	if len(buckets) == 0 {
		return nil
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	stmtTotals, err := tx.PrepareContext(ctx, `
INSERT INTO traffic_totals (service, bytes_in, bytes_out, requests, updated_at)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT(service) DO UPDATE SET
  bytes_in = bytes_in + excluded.bytes_in,
  bytes_out = bytes_out + excluded.bytes_out,
  requests = requests + excluded.requests,
  updated_at = excluded.updated_at;
`)
	if err != nil {
		return err
	}
	defer func() { _ = stmtTotals.Close() }()

	stmtBucket, err := tx.PrepareContext(ctx, `
INSERT INTO traffic_buckets (kind, start_ts, service, bytes_in, bytes_out, requests, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(kind, start_ts, service) DO UPDATE SET
  bytes_in = bytes_in + excluded.bytes_in,
  bytes_out = bytes_out + excluded.bytes_out,
  requests = requests + excluded.requests,
  updated_at = excluded.updated_at;
`)
	if err != nil {
		return err
	}
	defer func() { _ = stmtBucket.Close() }()

	for _, d := range deltas {
		svc := strings.TrimSpace(d.Service)
		if svc == "" {
			continue
		}
		if d.BytesIn == 0 && d.BytesOut == 0 && d.Requests == 0 {
			continue
		}

		if _, err := stmtTotals.ExecContext(ctx, svc, d.BytesIn, d.BytesOut, d.Requests, ts); err != nil {
			return err
		}

		for kind, startTS := range buckets {
			if _, err := stmtBucket.ExecContext(ctx, kind, startTS, svc, d.BytesIn, d.BytesOut, d.Requests, ts); err != nil {
				return err
			}
		}
	}

	return tx.Commit()
}

func GetTrafficTotals(ctx context.Context, db *sql.DB) (map[string]TrafficCounts, error) {
	if db == nil {
		return map[string]TrafficCounts{}, nil
	}

	rows, err := db.QueryContext(ctx, "SELECT service, bytes_in, bytes_out, requests FROM traffic_totals;")
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return map[string]TrafficCounts{}, nil
		}
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	out := map[string]TrafficCounts{}
	for rows.Next() {
		var svc string
		var c TrafficCounts
		if err := rows.Scan(&svc, &c.BytesIn, &c.BytesOut, &c.Requests); err != nil {
			return nil, err
		}
		svc = strings.TrimSpace(svc)
		if svc == "" {
			continue
		}
		out[svc] = c
	}
	return out, rows.Err()
}

func GetTrafficSeries(ctx context.Context, db *sql.DB, kind string, fromTS, toTS int64, sel TrafficServiceSelector) ([]TrafficSeriesPoint, error) {
	if db == nil {
		return []TrafficSeriesPoint{}, nil
	}
	if kind != trafficBucketHour && kind != trafficBucketDay && kind != trafficBucketMonth && kind != trafficBucketYear {
		return nil, fmt.Errorf("invalid traffic bucket kind: %q", kind)
	}
	if fromTS <= 0 || toTS <= 0 || toTS < fromTS {
		return nil, errors.New("invalid time range")
	}

	var query string
	var args []any

	switch sel.Mode {
	case "", "total":
		query = `
SELECT start_ts, SUM(bytes_in), SUM(bytes_out), SUM(requests)
FROM traffic_buckets
WHERE kind = ? AND start_ts >= ? AND start_ts <= ?
GROUP BY start_ts
ORDER BY start_ts ASC;
`
		args = []any{kind, fromTS, toTS}
	case "proxy_total":
		query = `
SELECT start_ts, SUM(bytes_in), SUM(bytes_out), SUM(requests)
FROM traffic_buckets
WHERE kind = ? AND start_ts >= ? AND start_ts <= ?
  AND (service = 'torcherino' OR service = 'cdnjs' OR service = 'git' OR service LIKE 'git:%')
GROUP BY start_ts
ORDER BY start_ts ASC;
`
		args = []any{kind, fromTS, toTS}
	case "exact":
		svc := strings.TrimSpace(sel.Service)
		if svc == "" {
			return []TrafficSeriesPoint{}, nil
		}
		query = `
SELECT start_ts, SUM(bytes_in), SUM(bytes_out), SUM(requests)
FROM traffic_buckets
WHERE kind = ? AND start_ts >= ? AND start_ts <= ? AND service = ?
GROUP BY start_ts
ORDER BY start_ts ASC;
`
		args = []any{kind, fromTS, toTS, svc}
	case "prefix":
		root := strings.TrimSpace(sel.Service)
		if root == "" {
			return []TrafficSeriesPoint{}, nil
		}
		query = `
SELECT start_ts, SUM(bytes_in), SUM(bytes_out), SUM(requests)
FROM traffic_buckets
WHERE kind = ? AND start_ts >= ? AND start_ts <= ? AND (service = ? OR service LIKE ?)
GROUP BY start_ts
ORDER BY start_ts ASC;
`
		args = []any{kind, fromTS, toTS, root, root + ":%"}
	default:
		return nil, fmt.Errorf("invalid selector mode: %q", sel.Mode)
	}

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	out := []TrafficSeriesPoint{}
	for rows.Next() {
		var p TrafficSeriesPoint
		if err := rows.Scan(&p.StartTS, &p.BytesIn, &p.BytesOut, &p.Requests); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func ClearTrafficStats(ctx context.Context, db *sql.DB) error {
	if db == nil {
		return nil
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, "DELETE FROM traffic_buckets;"); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM traffic_totals;"); err != nil {
		return err
	}
	return tx.Commit()
}

func GetTrafficRetention(ctx context.Context, db *sql.DB) (TrafficRetention, error) {
	ret := DefaultTrafficRetention()
	if db == nil {
		return ret, nil
	}

	readInt := func(key string, fallback int) (int, error) {
		var raw string
		err := db.QueryRowContext(ctx, "SELECT value FROM meta WHERE key = ?;", key).Scan(&raw)
		if errors.Is(err, sql.ErrNoRows) {
			return fallback, nil
		}
		if err != nil {
			return 0, err
		}
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return fallback, nil
		}
		n, err := strconv.Atoi(raw)
		if err != nil {
			return fallback, nil
		}
		if n < 0 {
			n = 0
		}
		return n, nil
	}

	var err error
	if ret.HourDays, err = readInt(metaKeyTrafficRetentionHourDays, ret.HourDays); err != nil {
		return TrafficRetention{}, err
	}
	if ret.DayDays, err = readInt(metaKeyTrafficRetentionDayDays, ret.DayDays); err != nil {
		return TrafficRetention{}, err
	}
	if ret.MonthMonths, err = readInt(metaKeyTrafficRetentionMonthMonths, ret.MonthMonths); err != nil {
		return TrafficRetention{}, err
	}
	if ret.YearYears, err = readInt(metaKeyTrafficRetentionYearYears, ret.YearYears); err != nil {
		return TrafficRetention{}, err
	}
	return ret, nil
}

func SetTrafficRetention(ctx context.Context, db *sql.DB, ret TrafficRetention) error {
	if db == nil {
		return nil
	}
	if ret.HourDays < 0 {
		ret.HourDays = 0
	}
	if ret.DayDays < 0 {
		ret.DayDays = 0
	}
	if ret.MonthMonths < 0 {
		ret.MonthMonths = 0
	}
	if ret.YearYears < 0 {
		ret.YearYears = 0
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	upsert := func(key string, val int) error {
		_, err := tx.ExecContext(ctx, `
INSERT INTO meta (key, value) VALUES (?, ?)
ON CONFLICT(key) DO UPDATE SET value = excluded.value;
`, key, strconv.Itoa(val))
		return err
	}

	for _, kv := range []struct {
		key string
		val int
	}{
		{metaKeyTrafficRetentionHourDays, ret.HourDays},
		{metaKeyTrafficRetentionDayDays, ret.DayDays},
		{metaKeyTrafficRetentionMonthMonths, ret.MonthMonths},
		{metaKeyTrafficRetentionYearYears, ret.YearYears},
	} {
		if err := upsert(kv.key, kv.val); err != nil {
			return err
		}
	}

	return tx.Commit()
}

func CleanupTrafficBuckets(ctx context.Context, db *sql.DB, retention TrafficRetention, now time.Time) (map[string]int64, error) {
	if db == nil {
		return map[string]int64{}, nil
	}
	now = now.UTC()

	cutoffs := map[string]int64{}

	if retention.HourDays > 0 {
		h0 := now.Truncate(time.Hour)
		cutoffs[trafficBucketHour] = h0.Add(-time.Duration(retention.HourDays) * 24 * time.Hour).Unix()
	}
	if retention.DayDays > 0 {
		d0 := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
		cutoffs[trafficBucketDay] = d0.Add(-time.Duration(retention.DayDays) * 24 * time.Hour).Unix()
	}
	if retention.MonthMonths > 0 {
		m0 := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
		cutoffs[trafficBucketMonth] = m0.AddDate(0, -retention.MonthMonths, 0).Unix()
	}
	if retention.YearYears > 0 {
		y0 := time.Date(now.Year(), 1, 1, 0, 0, 0, 0, time.UTC)
		cutoffs[trafficBucketYear] = y0.AddDate(-retention.YearYears, 0, 0).Unix()
	}

	if len(cutoffs) == 0 {
		return map[string]int64{}, nil
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	out := map[string]int64{}
	for kind, cutoff := range cutoffs {
		res, err := tx.ExecContext(ctx, "DELETE FROM traffic_buckets WHERE kind = ? AND start_ts < ?;", kind, cutoff)
		if err != nil {
			return nil, err
		}
		n, _ := res.RowsAffected()
		out[kind] = n
	}

	return out, tx.Commit()
}
