package rediscache

import (
	"crypto/sha256"
	"encoding/hex"
)

const MarkerKey = "hazuki:meta:app"
const MarkerValue = "hazuki-go"

type Namespace struct {
	Key      string
	Prefix   string
	IndexKey string
}

var Cdnjs = Namespace{
	Key:      "cdnjs",
	Prefix:   "hazuki:cdnjs:",
	IndexKey: "hazuki:cdnjs:index",
}

var Torcherino = Namespace{
	Key:      "torcherino",
	Prefix:   "hazuki:torcherino:",
	IndexKey: "hazuki:torcherino:index",
}

func CacheID(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

func BodyKey(ns Namespace, id string) string { return ns.Prefix + "body:" + id }
func TypeKey(ns Namespace, id string) string { return ns.Prefix + "type:" + id }
func MetaKey(ns Namespace, id string) string { return ns.Prefix + "meta:" + id }

func NamespaceByKey(key string) (Namespace, bool) {
	switch key {
	case "", Cdnjs.Key:
		return Cdnjs, true
	case Torcherino.Key:
		return Torcherino, true
	default:
		return Namespace{}, false
	}
}
