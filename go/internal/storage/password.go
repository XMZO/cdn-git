package storage

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/scrypt"
)

const (
	passwordHashVersion = "v1"
	passwordKeyLen      = 64
)

var passwordScryptParams = struct {
	N      int
	r      int
	p      int
	maxmem int
}{
	N:      32768,
	r:      8,
	p:      1,
	maxmem: 64 * 1024 * 1024,
}

func HashPassword(password string) (string, error) {
	if len(password) < 8 {
		return "", errors.New("Password must be at least 8 characters")
	}

	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	derived, err := scrypt.Key([]byte(password), salt, passwordScryptParams.N, passwordScryptParams.r, passwordScryptParams.p, passwordKeyLen)
	if err != nil {
		return "", err
	}

	return strings.Join([]string{
		"scrypt",
		passwordHashVersion,
		fmt.Sprintf("N=%d", passwordScryptParams.N),
		fmt.Sprintf("r=%d", passwordScryptParams.r),
		fmt.Sprintf("p=%d", passwordScryptParams.p),
		base64.StdEncoding.EncodeToString(salt),
		base64.StdEncoding.EncodeToString(derived),
	}, ":"), nil
}

func VerifyPassword(password, storedHash string) bool {
	parts := strings.Split(storedHash, ":")
	if len(parts) != 7 {
		return false
	}
	algo, version := parts[0], parts[1]
	if algo != "scrypt" || version != passwordHashVersion {
		return false
	}

	N, ok := parseHashInt(strings.TrimPrefix(parts[2], "N="))
	if !ok {
		return false
	}
	r, ok := parseHashInt(strings.TrimPrefix(parts[3], "r="))
	if !ok {
		return false
	}
	p, ok := parseHashInt(strings.TrimPrefix(parts[4], "p="))
	if !ok {
		return false
	}

	salt, err := base64.StdEncoding.DecodeString(parts[5])
	if err != nil {
		return false
	}
	expected, err := base64.StdEncoding.DecodeString(parts[6])
	if err != nil {
		return false
	}

	actual, err := scrypt.Key([]byte(password), salt, N, r, p, len(expected))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(actual, expected) == 1
}

func parseHashInt(v string) (int, bool) {
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return 0, false
	}
	return n, true
}

