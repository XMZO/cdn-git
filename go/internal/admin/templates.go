package admin

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"io/fs"
)

//go:embed ui/templates/*.html ui/templates/pages/*.html ui/templates/partials/*.html ui/assets/*
var uiFS embed.FS

var uiAssetsFS = mustSub(uiFS, "ui/assets")

var bodyTemplateAllowList = map[string]struct{}{
	"login":      {},
	"setup":      {},
	"dashboard":  {},
	"system":     {},
	"wizard":     {},
	"torcherino": {},
	"cdnjs":      {},
	"git":        {},
	"versions":   {},
	"import":     {},
	"account":    {},
}

var pageTemplates = mustLoadTemplates()

func mustSub(fsys fs.FS, dir string) fs.FS {
	sub, err := fs.Sub(fsys, dir)
	if err != nil {
		panic(err)
	}
	return sub
}

func mustLoadTemplates() *template.Template {
	t := template.New("layout")
	t = t.Funcs(template.FuncMap{
		"render": func(name string, data any) (template.HTML, error) {
			if _, ok := bodyTemplateAllowList[name]; !ok {
				return "", fmt.Errorf("unknown template: %q", name)
			}

			var buf bytes.Buffer
			if err := t.ExecuteTemplate(&buf, name, data); err != nil {
				return "", err
			}
			return template.HTML(buf.String()), nil
		},
	})

	template.Must(t.ParseFS(
		uiFS,
		"ui/templates/*.html",
		"ui/templates/pages/*.html",
		"ui/templates/partials/*.html",
	))
	return t
}
