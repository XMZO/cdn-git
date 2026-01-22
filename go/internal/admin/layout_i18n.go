package admin

import (
	"strings"

	"hazuki-go/internal/i18n"
)

func (d layoutData) T(key string, args ...any) string {
	return adminI18n.T(d.Lang, key, args...)
}

func (d layoutData) LangCode() string {
	l := i18n.NormalizeLang(d.Lang)
	if l == "" {
		return i18n.LangZH
	}
	return l
}

func (d layoutData) HTMLLang() string {
	switch d.LangCode() {
	case i18n.LangEN:
		return "en"
	default:
		return "zh-CN"
	}
}

func (d layoutData) IsLang(lang string) bool {
	return strings.EqualFold(d.LangCode(), i18n.NormalizeLang(lang))
}
