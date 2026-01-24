package admin

import (
	"net/http"
	"strconv"
	"strings"
)

func (s *server) configVersions(w http.ResponseWriter, r *http.Request) {
	st := getState(r.Context())
	title := s.t(r, "page.versions.title")
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	versions, err := s.config.ListVersions(100)
	if err != nil {
		s.render(w, r, versionsData{
			layoutData: layoutData{
				Title:        title,
				BodyTemplate: "versions",
				User:         st.User,
				HasUsers:     st.HasUsers,
				Error:        err.Error(),
			},
		})
		return
	}

	notice := ""
	if r.URL.Query().Get("ok") != "" {
		notice = s.t(r, "common.applied")
	}
	s.render(w, r, versionsData{
		layoutData: layoutData{
			Title:        title,
			BodyTemplate: "versions",
			User:         st.User,
			HasUsers:     st.HasUsers,
			Notice:       notice,
		},
		Versions: versions,
	})
}

func (s *server) configVersionsSub(w http.ResponseWriter, r *http.Request) {
	st := getState(r.Context())
	title := s.t(r, "page.versions.title")
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// /config/versions/{id}/restore
	path := strings.TrimPrefix(r.URL.Path, "/config/versions/")
	if !strings.HasSuffix(path, "/restore") {
		http.NotFound(w, r)
		return
	}
	idRaw := strings.TrimSuffix(path, "/restore")
	idRaw = strings.Trim(idRaw, "/")
	versionID, err := strconv.ParseInt(idRaw, 10, 64)
	if err != nil || versionID <= 0 {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	userID := st.User.ID
	if err := s.config.RestoreVersion(versionID, &userID); err != nil {
		versions, _ := s.config.ListVersions(100)
		s.render(w, r, versionsData{
			layoutData: layoutData{
				Title:        title,
				BodyTemplate: "versions",
				User:         st.User,
				HasUsers:     st.HasUsers,
				Error:        err.Error(),
			},
			Versions: versions,
		})
		return
	}

	http.Redirect(w, r, "/config/versions?ok=1", http.StatusFound)
}
