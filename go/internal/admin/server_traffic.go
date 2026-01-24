package admin

import (
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"hazuki-go/internal/model"
	"hazuki-go/internal/storage"
)

func (s *server) traffic(w http.ResponseWriter, r *http.Request) {
	st := getState(r.Context())
	title := s.t(r, "page.traffic.title")

	switch r.Method {
	case http.MethodGet:
		// continue
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ret, err := storage.GetTrafficRetention(r.Context(), s.db)
	if err != nil {
		s.render(w, r, trafficData{
			layoutData: layoutData{
				Title:        title,
				BodyTemplate: "traffic",
				User:         st.User,
				HasUsers:     st.HasUsers,
				Error:        err.Error(),
			},
		})
		return
	}

	notice := ""
	if r.URL.Query().Get("ok") != "" {
		notice = s.t(r, "common.saved")
	}
	if r.URL.Query().Get("cleared") != "" {
		notice = s.t(r, "traffic.cleared")
	}
	if r.URL.Query().Get("cleaned") != "" {
		notice = s.t(r, "traffic.cleaned")
	}

	cfg, err := s.config.GetDecryptedConfig()
	gitInstances := []trafficGitInstanceOption{}
	if err == nil && len(cfg.GitInstances) > 0 {
		sorted := append([]model.GitInstanceConfig(nil), cfg.GitInstances...)
		sort.Slice(sorted, func(i, j int) bool {
			return strings.ToLower(strings.TrimSpace(sorted[i].ID)) < strings.ToLower(strings.TrimSpace(sorted[j].ID))
		})
		for _, it := range sorted {
			id := strings.TrimSpace(it.ID)
			if id == "" {
				continue
			}
			name := strings.TrimSpace(it.Name)
			if name == "" {
				name = id
			}
			gitInstances = append(gitInstances, trafficGitInstanceOption{
				ID:    id,
				Name:  name,
				Value: "git:" + strings.ToLower(id),
			})
		}
	}

	s.render(w, r, trafficData{
		layoutData: layoutData{
			Title:        title,
			BodyTemplate: "traffic",
			User:         st.User,
			HasUsers:     st.HasUsers,
			Notice:       notice,
		},
		Retention:    ret,
		GitInstances: gitInstances,
	})
}

func (s *server) trafficRetention(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	parseInt := func(key string) int {
		raw := strings.TrimSpace(r.FormValue(key))
		if raw == "" {
			return 0
		}
		n, _ := strconv.Atoi(raw)
		if n < 0 {
			n = 0
		}
		return n
	}

	ret := storage.TrafficRetention{
		HourDays:    parseInt("hourDays"),
		DayDays:     parseInt("dayDays"),
		MonthMonths: parseInt("monthMonths"),
		YearYears:   parseInt("yearYears"),
	}

	if err := storage.SetTrafficRetention(r.Context(), s.db, ret); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	http.Redirect(w, r, "/traffic?ok=1", http.StatusFound)
}

func (s *server) trafficCleanup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ret, err := storage.GetTrafficRetention(r.Context(), s.db)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	if _, err := storage.CleanupTrafficBuckets(r.Context(), s.db, ret, time.Now()); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	http.Redirect(w, r, "/traffic?cleaned=1", http.StatusFound)
}

func (s *server) trafficClear(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.trafficPersist != nil {
		if err := s.trafficPersist.ClearAll(r.Context()); err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
	} else {
		if err := storage.ClearTrafficStats(r.Context(), s.db); err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
	}

	http.Redirect(w, r, "/traffic?cleared=1", http.StatusFound)
}

func (s *server) trafficSeries(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		// continue
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	kind := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("kind")))
	if kind == "" {
		kind = "hour"
	}

	service := strings.TrimSpace(r.URL.Query().Get("svc"))
	if service == "" {
		service = "total"
	}

	now := time.Now().UTC()
	var from time.Time
	var to time.Time
	switch kind {
	case "hour":
		to = now.Truncate(time.Hour)
		from = to.Add(-23 * time.Hour)
	case "day":
		to = time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
		from = to.Add(-29 * 24 * time.Hour)
	case "month":
		to = time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
		from = to.AddDate(0, -11, 0)
	case "year":
		to = time.Date(now.Year(), 1, 1, 0, 0, 0, 0, time.UTC)
		from = to.AddDate(-9, 0, 0)
	default:
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	sel := storage.TrafficServiceSelector{Mode: "proxy_total"}
	switch strings.ToLower(service) {
	case "total":
		sel = storage.TrafficServiceSelector{Mode: "proxy_total"}
	case "torcherino":
		sel = storage.TrafficServiceSelector{Mode: "exact", Service: "torcherino"}
	case "cdnjs":
		sel = storage.TrafficServiceSelector{Mode: "exact", Service: "cdnjs"}
	case "git":
		sel = storage.TrafficServiceSelector{Mode: "prefix", Service: "git"}
	case "sakuya":
		sel = storage.TrafficServiceSelector{Mode: "exact", Service: "sakuya"}
	case "admin":
		sel = storage.TrafficServiceSelector{Mode: "exact", Service: "admin"}
	default:
		if strings.HasPrefix(strings.ToLower(service), "git:") {
			sel = storage.TrafficServiceSelector{Mode: "exact", Service: strings.ToLower(service)}
		} else {
			// Unknown service selector: treat as exact raw key.
			sel = storage.TrafficServiceSelector{Mode: "exact", Service: service}
		}
	}

	minStartTS, err := storage.GetTrafficMinBucketStartTS(r.Context(), s.db, kind, sel)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	if minStartTS <= 0 {
		// No data for this selector yet: don't render fake empty buckets.
		payload := map[string]any{
			"ok":      true,
			"time":    time.Now().UTC().Format(time.RFC3339Nano),
			"kind":    kind,
			"service": service,
			"fromTs":  int64(0),
			"toTs":    int64(0),
			"points":  []storage.TrafficSeriesPoint{},
		}
		b, _ := json.Marshal(payload)

		w.Header().Set("content-type", "application/json; charset=utf-8")
		w.Header().Set("cache-control", "no-store")
		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodHead {
			return
		}
		_, _ = w.Write(b)
		return
	}

	minStartTime := time.Unix(minStartTS, 0).UTC()
	if minStartTime.After(from) {
		from = minStartTime
	}
	if from.After(to) {
		from = to
	}

	points, err := storage.GetTrafficSeries(r.Context(), s.db, kind, from.Unix(), to.Unix(), sel)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	// Fill missing buckets server-side (UTC bucket starts).
	out := make([]storage.TrafficSeriesPoint, 0, 64)
	existing := map[int64]storage.TrafficCounts{}
	for _, p := range points {
		existing[p.StartTS] = storage.TrafficCounts{BytesIn: p.BytesIn, BytesOut: p.BytesOut, Requests: p.Requests}
	}

	cur := from
	for !cur.After(to) {
		ts := cur.Unix()
		c := existing[ts]
		out = append(out, storage.TrafficSeriesPoint{
			StartTS: ts,
			TrafficCounts: storage.TrafficCounts{
				BytesIn:  c.BytesIn,
				BytesOut: c.BytesOut,
				Requests: c.Requests,
			},
		})

		switch kind {
		case "hour":
			cur = cur.Add(time.Hour)
		case "day":
			cur = cur.Add(24 * time.Hour)
		case "month":
			cur = cur.AddDate(0, 1, 0)
		case "year":
			cur = cur.AddDate(1, 0, 0)
		}
	}

	payload := map[string]any{
		"ok":      true,
		"time":    time.Now().UTC().Format(time.RFC3339Nano),
		"kind":    kind,
		"service": service,
		"fromTs":  from.Unix(),
		"toTs":    to.Unix(),
		"points":  out,
	}
	b, _ := json.Marshal(payload)

	w.Header().Set("content-type", "application/json; charset=utf-8")
	w.Header().Set("cache-control", "no-store")
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(b)
}
