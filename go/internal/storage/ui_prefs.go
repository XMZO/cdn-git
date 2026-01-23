package storage

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"strings"
)

const metaKeyAdminTimeZone = "admin_time_zone"

// GetAdminTimeZone returns the persisted UI timezone spec for the admin panel.
//
// Supported values (by convention):
//   - "auto" (default): use browser local time
//   - "UTC": show times in UTC
//   - "+08:00" / "-05:30": fixed offset
func GetAdminTimeZone(ctx context.Context, db *sql.DB) (string, error) {
	if db == nil {
		return "auto", nil
	}
	var raw string
	err := db.QueryRowContext(ctx, "SELECT value FROM meta WHERE key = ?;", metaKeyAdminTimeZone).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return "auto", nil
	}
	if err != nil {
		return "", err
	}
	v := strings.TrimSpace(raw)
	if v == "" {
		return "auto", nil
	}
	return v, nil
}

func SetAdminTimeZone(ctx context.Context, db *sql.DB, tz string) error {
	if db == nil {
		return nil
	}
	v := strings.TrimSpace(tz)
	if v == "" {
		v = "auto"
	}

	_, err := db.ExecContext(ctx, `
INSERT INTO meta (key, value) VALUES (?, ?)
ON CONFLICT(key) DO UPDATE SET value = excluded.value;
`, metaKeyAdminTimeZone, v)
	return err
}

// ParseTimeZoneOffsetMinutes parses a fixed UTC offset spec into minutes.
// Accepted forms: "+8", "+08", "+08:00", "+0800", "-5:30", "UTC+8", "UTC-0530", "UTC", "Z".
func ParseTimeZoneOffsetMinutes(spec string) (offsetMinutes int, ok bool) {
	s := strings.TrimSpace(spec)
	if s == "" {
		return 0, false
	}
	sl := strings.ToLower(s)
	if sl == "utc" || sl == "z" {
		return 0, true
	}
	if strings.HasPrefix(sl, "utc") {
		s = strings.TrimSpace(s[3:])
		if s == "" {
			return 0, true
		}
	}

	if len(s) < 2 {
		return 0, false
	}
	sign := 1
	switch s[0] {
	case '+':
		sign = 1
	case '-':
		sign = -1
	default:
		return 0, false
	}
	rest := strings.TrimSpace(s[1:])
	rest = strings.ReplaceAll(rest, " ", "")
	rest = strings.ReplaceAll(rest, ":", "")

	if rest == "" {
		return 0, false
	}
	// "+H", "+HH", "+HHMM"
	if len(rest) != 1 && len(rest) != 2 && len(rest) != 4 {
		return 0, false
	}

	hoursStr := rest
	minStr := "0"
	if len(rest) == 4 {
		hoursStr = rest[:2]
		minStr = rest[2:]
	}

	hours, err := strconv.Atoi(hoursStr)
	if err != nil {
		return 0, false
	}
	minutes, err := strconv.Atoi(minStr)
	if err != nil {
		return 0, false
	}
	if hours < 0 || hours > 14 || minutes < 0 || minutes > 59 {
		return 0, false
	}
	total := sign * (hours*60 + minutes)
	if total < -14*60 || total > 14*60 {
		return 0, false
	}
	return total, true
}

func FormatTimeZoneOffsetMinutes(offsetMinutes int) (spec string, ok bool) {
	if offsetMinutes < -14*60 || offsetMinutes > 14*60 {
		return "", false
	}
	sign := "+"
	n := offsetMinutes
	if n < 0 {
		sign = "-"
		n = -n
	}
	h := n / 60
	m := n % 60
	return sign + pad2(h) + ":" + pad2(m), true
}

func pad2(n int) string {
	if n < 10 {
		return "0" + strconv.Itoa(n)
	}
	return strconv.Itoa(n)
}
