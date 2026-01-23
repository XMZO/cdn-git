package sakuyaproxy

import (
	"testing"
	"time"
)

func TestVerifySign(t *testing.T) {
	token := "test-token"
	path := "/foo/bar"

	now := time.Unix(2000, 0).UTC()
	expire := int64(3000)
	sign := hmacSha256Sign(path, expire, token)

	if msg := verifySign(path, sign, token, now); msg != "" {
		t.Fatalf("verifySign should pass, got: %q", msg)
	}

	if msg := verifySign(path, "", token, now); msg != "expire missing" {
		t.Fatalf("empty sign: got %q", msg)
	}
	if msg := verifySign(path, "abc:", token, now); msg != "expire missing" {
		t.Fatalf("missing expire: got %q", msg)
	}
	if msg := verifySign(path, "abc", token, now); msg != "expire invalid" {
		t.Fatalf("invalid expire: got %q", msg)
	}

	expiredSign := hmacSha256Sign(path, 100, token)
	if msg := verifySign(path, expiredSign, token, now); msg != "expire expired" {
		t.Fatalf("expired: got %q", msg)
	}

	bad := hmacSha256Sign(path, expire, "wrong-token")
	if msg := verifySign(path, bad, token, now); msg != "sign mismatch" {
		t.Fatalf("mismatch: got %q", msg)
	}
}
