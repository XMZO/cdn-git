package admin

import (
	"context"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"reflect"
	"strings"

	"hazuki-go/internal/i18n"
	"hazuki-go/internal/storage"
)

const cookieName = "hazuki_session"
const langCookieName = "hazuki_lang"

func (s *server) wrap(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		st, err := s.buildState(r)
		if err != nil {
			http.Error(w, "Bad gateway", http.StatusBadGateway)
			return
		}

		// If no users exist, force setup (except setup/health).
		if !st.HasUsers && r.URL.Path != "/setup" && !strings.HasPrefix(r.URL.Path, "/_hazuki/health") {
			http.Redirect(w, r, "/setup", http.StatusFound)
			return
		}

		ctx := context.WithValue(r.Context(), stateKey, st)
		next(w, r.WithContext(ctx))
	}
}

func (s *server) wrapRequireAuth(next http.HandlerFunc) http.HandlerFunc {
	return s.wrap(func(w http.ResponseWriter, r *http.Request) {
		st := getState(r.Context())
		if st == nil || st.User == nil {
			if st != nil && !st.HasUsers {
				http.Redirect(w, r, "/setup", http.StatusFound)
				return
			}
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		next(w, r)
	})
}

func (s *server) buildState(r *http.Request) (*reqState, error) {
	count, err := storage.CountUsers(s.db)
	if err != nil {
		return nil, err
	}
	st := &reqState{HasUsers: count > 0}

	cookie, err := r.Cookie(cookieName)
	if err != nil {
		return st, nil
	}
	user, ok, err := storage.GetSessionUser(s.db, cookie.Value)
	if err != nil {
		return nil, err
	}
	if ok {
		st.User = &user
	}
	return st, nil
}

func getState(ctx context.Context) *reqState {
	v := ctx.Value(stateKey)
	st, _ := v.(*reqState)
	return st
}

func (s *server) render(w http.ResponseWriter, r *http.Request, data any) {
	w.Header().Set("content-type", "text/html; charset=utf-8")
	lang := s.pickLang(r)
	tz := s.pickTimeZone(r)
	data = injectLayoutData(data, lang, tz)
	_ = pageTemplates.ExecuteTemplate(w, "layout", data)
}

func (s *server) pickLang(r *http.Request) string {
	if r == nil {
		return i18n.LangZH
	}

	if q := i18n.NormalizeLang(r.URL.Query().Get("lang")); q != "" {
		return q
	}

	if c, err := r.Cookie(langCookieName); err == nil {
		if v := i18n.NormalizeLang(c.Value); v != "" {
			return v
		}
	}

	return i18n.NegotiateLang(r.Header.Get("Accept-Language"), i18n.LangZH)
}

func (s *server) pickTimeZone(r *http.Request) string {
	if r == nil {
		return "auto"
	}
	tz, err := storage.GetAdminTimeZone(r.Context(), s.db)
	if err != nil {
		return "auto"
	}
	return tz
}

func (s *server) t(r *http.Request, key string, args ...any) string {
	return adminI18n.T(s.pickLang(r), key, args...)
}

type i18nError interface {
	I18n() (string, []any)
}

type errKey struct {
	key  string
	args []any
}

func (e errKey) Error() string { return e.key }

func (e errKey) I18n() (string, []any) { return e.key, e.args }

func errI18n(key string, args ...any) error {
	return errKey{key: key, args: args}
}

func (s *server) errText(r *http.Request, err error) string {
	if err == nil {
		return ""
	}
	var ie i18nError
	if errors.As(err, &ie) {
		key, args := ie.I18n()
		return s.t(r, key, args...)
	}
	return err.Error()
}

func injectLayoutData(data any, lang string, tz string) any {
	if data == nil {
		return data
	}

	jsMap := adminI18n.Export(lang, "js.")
	jsBytes, _ := json.Marshal(jsMap)

	v := reflect.ValueOf(data)

	// Fast-path: pointer to struct.
	if v.Kind() == reflect.Ptr && !v.IsNil() && v.Elem().Kind() == reflect.Struct {
		if f := v.Elem().FieldByName("Lang"); f.IsValid() && f.CanSet() && f.Kind() == reflect.String {
			f.SetString(lang)
		}
		if f := v.Elem().FieldByName("JSI18n"); f.IsValid() && f.CanSet() {
			if f.Type() == reflect.TypeOf(template.JS("")) {
				f.Set(reflect.ValueOf(template.JS(string(jsBytes))))
			}
		}
		if f := v.Elem().FieldByName("TimeZone"); f.IsValid() && f.CanSet() && f.Kind() == reflect.String {
			f.SetString(tz)
		}
		return data
	}

	// Struct value: copy into a new pointer so we can set fields.
	if v.Kind() == reflect.Struct {
		p := reflect.New(v.Type())
		p.Elem().Set(v)
		if f := p.Elem().FieldByName("Lang"); f.IsValid() && f.CanSet() && f.Kind() == reflect.String {
			f.SetString(lang)
		}
		if f := p.Elem().FieldByName("JSI18n"); f.IsValid() && f.CanSet() {
			if f.Type() == reflect.TypeOf(template.JS("")) {
				f.Set(reflect.ValueOf(template.JS(string(jsBytes))))
			}
		}
		if f := p.Elem().FieldByName("TimeZone"); f.IsValid() && f.CanSet() && f.Kind() == reflect.String {
			f.SetString(tz)
		}
		return p.Interface()
	}

	return data
}
