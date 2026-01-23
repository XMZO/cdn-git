package admin

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

func syncMasterKeyToDotEnv(newMasterKey string) (bool, error) {
	if strings.ContainsAny(newMasterKey, "\r\n") {
		return false, errors.New("invalid master key")
	}

	candidates := []string{}
	if p := strings.TrimSpace(os.Getenv("HAZUKI_ENV_FILE")); p != "" {
		candidates = append(candidates, p)
	} else {
		candidates = append(candidates, filepath.Join("go", ".env"), ".env")
	}

	var lastErr error
	for _, p := range candidates {
		updated, err := updateDotEnvKey(p, "HAZUKI_MASTER_KEY", newMasterKey)
		if err == nil && updated {
			return true, nil
		}
		if err != nil {
			lastErr = err
		}
	}
	return false, lastErr
}

func updateDotEnvKey(path, key, value string) (bool, error) {
	if strings.TrimSpace(path) == "" {
		return false, errors.New("env file path is empty")
	}
	if strings.TrimSpace(key) == "" {
		return false, errors.New("env key is empty")
	}
	if strings.ContainsAny(value, "\r\n") {
		return false, errors.New("env value contains newline")
	}

	b, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}

	newline := "\n"
	raw := string(b)
	if strings.Contains(raw, "\r\n") {
		newline = "\r\n"
		raw = strings.ReplaceAll(raw, "\r\n", "\n")
	}

	lines := strings.Split(raw, "\n")

	replaced := false
	for i := range lines {
		prefix, comment, ok := splitDotEnvLinePrefixForKey(lines[i], key)
		if !ok {
			continue
		}
		next := prefix + value
		if comment != "" {
			next += " " + comment
		}
		lines[i] = next
		replaced = true
		break
	}
	if !replaced {
		if len(lines) == 0 {
			lines = append(lines, key+"="+value)
		} else {
			// Keep an existing trailing newline, if any.
			if lines[len(lines)-1] != "" {
				lines = append(lines, "")
			}
			lines = append(lines, key+"="+value)
		}
	}

	out := strings.Join(lines, "\n")
	if newline == "\r\n" {
		out = strings.ReplaceAll(out, "\n", "\r\n")
	}

	mode := os.FileMode(0o600)
	if st, err := os.Stat(path); err == nil {
		mode = st.Mode()
	}

	tmpDir := filepath.Dir(path)
	tmp, err := os.CreateTemp(tmpDir, "hazuki-env-*")
	if err != nil {
		return false, err
	}
	tmpName := tmp.Name()
	_, werr := tmp.WriteString(out)
	cerr := tmp.Close()
	if werr != nil {
		_ = os.Remove(tmpName)
		return false, werr
	}
	if cerr != nil {
		_ = os.Remove(tmpName)
		return false, cerr
	}
	_ = os.Chmod(tmpName, mode)

	if err := os.Rename(tmpName, path); err != nil {
		backup := path + ".bak"
		_ = os.Remove(backup)
		if err2 := os.Rename(path, backup); err2 != nil {
			_ = os.Remove(tmpName)
			return false, err
		}
		if err2 := os.Rename(tmpName, path); err2 != nil {
			_ = os.Rename(backup, path)
			_ = os.Remove(tmpName)
			return false, err2
		}
		_ = os.Remove(backup)
	}

	return true, nil
}

func splitDotEnvLinePrefixForKey(line, key string) (prefix string, comment string, ok bool) {
	if line == "" {
		return "", "", false
	}

	commentIdx := -1
	for i := 0; i < len(line); i++ {
		if line[i] == '#' && i > 0 && (line[i-1] == ' ' || line[i-1] == '\t') {
			commentIdx = i
			break
		}
	}
	base := line
	if commentIdx >= 0 {
		base = line[:commentIdx]
		comment = strings.TrimSpace(line[commentIdx:])
	}

	// leading whitespace
	ws := 0
	for ws < len(base) && (base[ws] == ' ' || base[ws] == '\t') {
		ws++
	}
	indent := base[:ws]
	rest := base[ws:]

	// optional "export" (keep original spacing)
	if strings.HasPrefix(rest, "export") {
		if len(rest) > len("export") && (rest[len("export")] == ' ' || rest[len("export")] == '\t') {
			j := len("export")
			for j < len(rest) && (rest[j] == ' ' || rest[j] == '\t') {
				j++
			}
			// keep "export   "
			rest = rest[j:]
			indent = indent + base[ws:ws+j]
		}
	}

	if !strings.HasPrefix(rest, key) {
		return "", "", false
	}
	i := len(key)
	for i < len(rest) && (rest[i] == ' ' || rest[i] == '\t') {
		i++
	}
	if i >= len(rest) || rest[i] != '=' {
		return "", "", false
	}
	i++ // include '='
	for i < len(rest) && (rest[i] == ' ' || rest[i] == '\t') {
		i++
	}
	prefix = indent + rest[:i]
	return prefix, comment, true
}
