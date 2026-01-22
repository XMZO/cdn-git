package storage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/scrypt"
)

const (
	metaKeyKdfSalt = "kdf_salt_b64"
	encPrefix      = "enc:v1:"
)

var ErrDecryptAuthFailed = errors.New("decrypt: message authentication failed")

type CryptoContext struct {
	Enabled bool
	key     []byte
}

func NewCryptoContext(db *sql.DB, masterKey string) (*CryptoContext, error) {
	saltB64, err := ensureKdfSalt(db)
	if err != nil {
		return nil, err
	}

	if strings.TrimSpace(masterKey) == "" {
		return &CryptoContext{Enabled: false}, nil
	}

	salt, err := base64.StdEncoding.DecodeString(saltB64)
	if err != nil {
		return nil, err
	}

	// Node crypto.scryptSync defaults: N=16384, r=8, p=1.
	key, err := scrypt.Key([]byte(masterKey), salt, 16384, 8, 1, 32)
	if err != nil {
		return nil, err
	}

	return &CryptoContext{Enabled: true, key: key}, nil
}

func NewCryptoContextFromSalt(masterKey, saltB64 string) (*CryptoContext, error) {
	if strings.TrimSpace(masterKey) == "" {
		return &CryptoContext{Enabled: false}, nil
	}
	salt, err := base64.StdEncoding.DecodeString(strings.TrimSpace(saltB64))
	if err != nil {
		return nil, err
	}

	// Node crypto.scryptSync defaults: N=16384, r=8, p=1.
	key, err := scrypt.Key([]byte(masterKey), salt, 16384, 8, 1, 32)
	if err != nil {
		return nil, err
	}
	return &CryptoContext{Enabled: true, key: key}, nil
}

func GetKdfSaltB64(db *sql.DB) (string, error) {
	return ensureKdfSalt(db)
}

func (c *CryptoContext) EncryptString(plaintext string) (string, error) {
	if !c.Enabled || strings.TrimSpace(plaintext) == "" {
		return plaintext, nil
	}
	if strings.HasPrefix(plaintext, encPrefix) {
		return plaintext, nil
	}

	block, err := aes.NewCipher(c.key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	iv := make([]byte, 12)
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}

	ctWithTag := gcm.Seal(nil, iv, []byte(plaintext), nil)
	if len(ctWithTag) < gcm.Overhead() {
		return "", errors.New("encrypt: ciphertext too short")
	}
	tagLen := gcm.Overhead()
	ciphertext := ctWithTag[:len(ctWithTag)-tagLen]
	tag := ctWithTag[len(ctWithTag)-tagLen:]

	combined := make([]byte, 0, len(iv)+len(tag)+len(ciphertext))
	combined = append(combined, iv...)
	combined = append(combined, tag...)
	combined = append(combined, ciphertext...)

	return encPrefix + base64.StdEncoding.EncodeToString(combined), nil
}

func (c *CryptoContext) DecryptString(value string) (string, error) {
	if strings.TrimSpace(value) == "" {
		return value, nil
	}
	if !strings.HasPrefix(value, encPrefix) {
		return value, nil
	}
	if !c.Enabled {
		return "", errors.New("HAZUKI_MASTER_KEY is required to decrypt stored secrets")
	}

	b64 := strings.TrimPrefix(value, encPrefix)
	combined, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", err
	}
	if len(combined) < 12+16 {
		return "", errors.New("decrypt: payload too short")
	}
	iv := combined[:12]
	tag := combined[12:28]
	ciphertext := combined[28:]

	block, err := aes.NewCipher(c.key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	ctWithTag := make([]byte, 0, len(ciphertext)+len(tag))
	ctWithTag = append(ctWithTag, ciphertext...)
	ctWithTag = append(ctWithTag, tag...)

	plaintext, err := gcm.Open(nil, iv, ctWithTag, nil)
	if err != nil {
		if strings.Contains(err.Error(), "message authentication failed") {
			return "", errors.Join(ErrDecryptAuthFailed, err)
		}
		return "", err
	}
	return string(plaintext), nil
}

func ensureKdfSalt(db *sql.DB) (string, error) {
	var value string
	err := db.QueryRow("SELECT value FROM meta WHERE key = ?", metaKeyKdfSalt).Scan(&value)
	if err == nil && strings.TrimSpace(value) != "" {
		return strings.TrimSpace(value), nil
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}

	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	salt := base64.StdEncoding.EncodeToString(b)

	_, err = db.Exec("INSERT INTO meta (key, value) VALUES (?, ?)", metaKeyKdfSalt, salt)
	if err != nil {
		return "", fmt.Errorf("insert kdf salt: %w", err)
	}
	return salt, nil
}
