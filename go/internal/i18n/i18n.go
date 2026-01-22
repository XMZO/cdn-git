package i18n

import (
	"fmt"
	"strings"
)

const (
	LangZH = "zh"
	LangEN = "en"
)

func NormalizeLang(v string) string {
	s := strings.ToLower(strings.TrimSpace(v))
	s = strings.ReplaceAll(s, "_", "-")
	switch {
	case s == "", s == "auto":
		return ""
	case s == "zh", strings.HasPrefix(s, "zh-"):
		return LangZH
	case s == "en", strings.HasPrefix(s, "en-"):
		return LangEN
	default:
		return ""
	}
}

func NegotiateLang(acceptLanguage string, fallback string) string {
	fallback = NormalizeLang(fallback)
	if fallback == "" {
		fallback = LangZH
	}

	raw := strings.TrimSpace(acceptLanguage)
	if raw == "" {
		return fallback
	}

	parts := strings.Split(raw, ",")
	for _, part := range parts {
		tag := strings.TrimSpace(part)
		if tag == "" {
			continue
		}
		if idx := strings.Index(tag, ";"); idx != -1 {
			tag = strings.TrimSpace(tag[:idx])
		}
		lang := NormalizeLang(tag)
		if lang != "" {
			return lang
		}
	}

	return fallback
}

type Bundle struct {
	fallback string
	byLang   map[string]map[string]string
}

func NewBundle(fallback string) *Bundle {
	f := NormalizeLang(fallback)
	if f == "" {
		f = LangZH
	}
	return &Bundle{
		fallback: f,
		byLang:   map[string]map[string]string{},
	}
}

func (b *Bundle) Register(lang string, messages map[string]string) {
	l := NormalizeLang(lang)
	if l == "" {
		panic("i18n: invalid lang: " + lang)
	}
	if messages == nil {
		return
	}
	dst, ok := b.byLang[l]
	if !ok {
		dst = map[string]string{}
		b.byLang[l] = dst
	}
	for k, v := range messages {
		key := strings.TrimSpace(k)
		if key == "" {
			continue
		}
		dst[key] = v
	}
}

func (b *Bundle) Lookup(lang string, key string) (string, bool) {
	l := NormalizeLang(lang)
	if l != "" {
		if m, ok := b.byLang[l]; ok {
			if v, ok := m[key]; ok {
				return v, true
			}
		}
	}
	if m, ok := b.byLang[b.fallback]; ok {
		if v, ok := m[key]; ok {
			return v, true
		}
	}
	return "", false
}

func (b *Bundle) Export(lang string, prefix string) map[string]string {
	out := map[string]string{}
	prefix = strings.TrimSpace(prefix)

	if m, ok := b.byLang[b.fallback]; ok {
		for k, v := range m {
			if prefix == "" || strings.HasPrefix(k, prefix) {
				out[k] = v
			}
		}
	}

	l := NormalizeLang(lang)
	if l != "" && l != b.fallback {
		if m, ok := b.byLang[l]; ok {
			for k, v := range m {
				if prefix == "" || strings.HasPrefix(k, prefix) {
					out[k] = v
				}
			}
		}
	}

	return out
}

func (b *Bundle) T(lang string, key string, args ...any) string {
	key = strings.TrimSpace(key)
	if key == "" {
		return ""
	}

	msg, ok := b.Lookup(lang, key)
	if !ok {
		return key
	}

	if len(args) == 0 {
		return msg
	}
	return fmt.Sprintf(msg, args...)
}
