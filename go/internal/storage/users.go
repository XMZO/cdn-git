package storage

import (
	"database/sql"
	"errors"
	"strings"
	"time"
)

type User struct {
	ID       int64
	Username string
}

func CountUsers(db *sql.DB) (int, error) {
	var c int
	if err := db.QueryRow("SELECT COUNT(1) AS c FROM users").Scan(&c); err != nil {
		return 0, err
	}
	return c, nil
}

func CreateUser(db *sql.DB, username, password string) (User, error) {
	u := strings.TrimSpace(username)
	if u == "" {
		return User{}, badRequest("Username is required")
	}
	if strings.TrimSpace(password) == "" {
		return User{}, badRequest("Password is required")
	}

	passwordHash, err := HashPassword(password)
	if err != nil {
		return User{}, badRequest(err.Error())
	}

	ts := nowIso()
	res, err := db.Exec("INSERT INTO users (username, password_hash, created_at, updated_at) VALUES (?, ?, ?, ?)", u, passwordHash, ts, ts)
	if err != nil {
		return User{}, err
	}
	id, _ := res.LastInsertId()
	return User{ID: id, Username: u}, nil
}

func EnsureBootstrapAdmin(db *sql.DB, username, password string) (bool, error) {
	n, err := CountUsers(db)
	if err != nil {
		return false, err
	}
	if n > 0 {
		return false, nil
	}
	u := strings.TrimSpace(username)
	p := strings.TrimSpace(password)
	if u == "" || p == "" {
		return false, nil
	}
	_, err = CreateUser(db, u, p)
	if err != nil {
		return false, err
	}
	return true, nil
}

func VerifyUserPassword(db *sql.DB, username, password string) (User, bool, error) {
	u := strings.TrimSpace(username)
	if u == "" {
		return User{}, false, nil
	}

	var id int64
	var uname string
	var passwordHash string
	if err := db.QueryRow("SELECT id, username, password_hash FROM users WHERE username = ?", u).Scan(&id, &uname, &passwordHash); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return User{}, false, nil
		}
		return User{}, false, err
	}
	ok := VerifyPassword(password, passwordHash)
	if !ok {
		return User{}, false, nil
	}
	return User{ID: id, Username: uname}, true, nil
}

func UpdateUserPassword(db *sql.DB, userID int64, newPassword string) error {
	passwordHash, err := HashPassword(newPassword)
	if err != nil {
		return badRequest(err.Error())
	}
	ts := nowIso()
	_, err = db.Exec("UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?", passwordHash, ts, userID)
	return err
}

type httpError struct {
	StatusCode int
	Message    string
}

func (e *httpError) Error() string { return e.Message }

func badRequest(msg string) error {
	return &httpError{StatusCode: 400, Message: msg}
}

func nowIso() string {
	return time.Now().UTC().Format(time.RFC3339Nano)
}

