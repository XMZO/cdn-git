package admin

import (
	"bytes"
	"html/template"
	"testing"

	"hazuki-go/internal/model"
	"hazuki-go/internal/storage"
)

func TestTemplatesRender(t *testing.T) {
	adminUser := &storage.User{ID: 1, Username: "admin"}

	cases := []struct {
		name string
		data any
	}{
		{
			name: "login",
			data: layoutData{Title: "登录", BodyTemplate: "login", HasUsers: true},
		},
		{
			name: "setup",
			data: layoutData{Title: "初始化管理员", BodyTemplate: "setup", HasUsers: false},
		},
		{
			name: "dashboard",
			data: dashboardData{
				layoutData:          layoutData{Title: "概览", BodyTemplate: "dashboard", User: adminUser, HasUsers: true},
				UpdatedAt:           "2026-01-01 00:00:00",
				Ports:               model.PortsConfig{Admin: 3100, Torcherino: 3000, Cdnjs: 3001, Git: 3002, Sakuya: 3200},
				AdminURL:            "http://127.0.0.1:3100",
				TorcherinoURL:       "http://127.0.0.1:3000",
				TorcherinoHealthURL: "http://127.0.0.1:3000/_hazuki/health",
				CdnjsURL:            "http://127.0.0.1:3001",
				CdnjsHealthURL:      "http://127.0.0.1:3001/_hazuki/health",
				GitURL:              "http://127.0.0.1:3002",
				GitHealthURL:        "http://127.0.0.1:3002/_hazuki/health",
			},
		},
		{
			name: "system",
			data: systemData{
				layoutData: layoutData{Title: "系统", BodyTemplate: "system", User: adminUser, HasUsers: true},

				GoVersion:         "go1.23.0",
				BuildVersion:      "devel",
				Uptime:            "1m0s",
				StartedAt:         "2026-01-01T00:00:00Z",
				Now:               "2026-01-01T00:01:00Z",
				SessionTTLSeconds: 86400,

				EncryptionEnabled: false,
				ConfigUpdatedAt:   "2026-01-01 00:00:00",

				DBPath:        "/data/hazuki.db",
				DBSize:        "1.0 MB",
				UsersCount:    1,
				VersionsCount: 2,
				SessionsCount: 3,

				Ports: model.PortsConfig{Admin: 3100, Torcherino: 3000, Cdnjs: 3001, Git: 3002, Sakuya: 3200},

				AdminStatus:        serviceStatus{Status: "ok", LatencyMS: 1},
				TorcherinoStatus:   serviceStatus{Status: "ok", LatencyMS: 1},
				CdnjsStatus:        serviceStatus{Status: "ok", LatencyMS: 1},
				GitStatus:          serviceStatus{Status: "ok", LatencyMS: 1},
				SakuyaOplistStatus: serviceStatus{Status: "disabled"},

				Redis: redisStatus{
					Addr:          "redis:6379",
					Status:        "ok",
					LatencyMS:     1,
					ServerVersion: "7.0.0",
					DBSize:        10,
				},
			},
		},
		{
			name: "wizard",
			data: wizardData{
				layoutData: layoutData{Title: "快速向导", BodyTemplate: "wizard", User: adminUser, HasUsers: true},
			},
		},
		{
			name: "torcherino",
			data: torcherinoData{
				layoutData:                     layoutData{Title: "Torcherino", BodyTemplate: "torcherino", User: adminUser, HasUsers: true},
				TorcherinoPortValue:            "3000",
				HostMappingJSON:                "{}",
				TorcherinoBaseURL:              "http://127.0.0.1:3000",
				TorcherinoHealthURL:            "http://127.0.0.1:3000/_hazuki/health",
				WorkerSecretHeaderMapJSONValue: "{}",
			},
		},
		{
			name: "cdnjs",
			data: cdnjsData{
				layoutData:        layoutData{Title: "jsDelivr 缓存", BodyTemplate: "cdnjs", User: adminUser, HasUsers: true},
				CdnjsPortValue:    "3001",
				AllowedUsersCsv:   "XMZO",
				RedisPortValue:    "6379",
				DefaultTTLValue:   "86400",
				TTLOverridesValue: "mjs=2592000",
				TTLEffectiveJSON:  template.JS(`{"defaultTTLSeconds":86400,"ttlByExt":{}}`),
				CdnjsBaseURL:      "http://127.0.0.1:3001",
				CdnjsHealthURL:    "http://127.0.0.1:3001/_hazuki/health",
			},
		},
		{
			name: "git",
			data: gitData{
				layoutData:        layoutData{Title: "GitHub Raw", BodyTemplate: "git", User: adminUser, HasUsers: true},
				GitPortValue:      "3002",
				ReplaceDictJson:   `{"$upstream":"$custom_domain"}`,
				GitBaseURL:        "http://127.0.0.1:3002",
				GitHealthURL:      "http://127.0.0.1:3002/_hazuki/health",
				BlockedRegionsCsv: "",
				BlockedIPsCsv:     "",
			},
		},
		{
			name: "sakuya_oplist",
			data: sakuyaOplistData{
				layoutData:           layoutData{Title: "Sakuya · Oplist", BodyTemplate: "sakuya_oplist", User: adminUser, HasUsers: true},
				Sakuya:               model.SakuyaConfig{Disabled: false},
				SakuyaPortValue:      "3200",
				OplistAddressValue:   "https://op.example.com",
				OplistPublicURLValue: "https://download.example.com",
				TokenIsSet:           true,
				SakuyaBaseURL:        "http://127.0.0.1:3200",
				SakuyaHealthURL:      "http://127.0.0.1:3200/_hazuki/health",
				SakuyaStatus:         serviceStatus{Status: "disabled"},
			},
		},
		{
			name: "versions",
			data: versionsData{
				layoutData: layoutData{Title: "版本 & 备份", BodyTemplate: "versions", User: adminUser, HasUsers: true},
			},
		},
		{
			name: "import",
			data: importData{
				layoutData: layoutData{Title: "导入备份", BodyTemplate: "import", User: adminUser, HasUsers: true},
				ConfigJSON: "{}",
			},
		},
		{
			name: "account",
			data: accountData{
				layoutData: layoutData{Title: "账号", BodyTemplate: "account", User: adminUser, HasUsers: true},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := pageTemplates.ExecuteTemplate(&buf, "layout", tc.data); err != nil {
				t.Fatalf("render failed: %v", err)
			}
			if buf.Len() == 0 {
				t.Fatalf("empty html output")
			}
		})
	}
}
