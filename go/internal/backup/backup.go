package backup

import (
	"bufio"
	"compress/gzip"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"

	"golang.org/x/crypto/argon2"

	"hazuki-go/internal/model"
	"hazuki-go/internal/storage"
)

const (
	fileMagic   = "HZBK"
	streamMagic = "HZD1"
	fileVersion = 1
)

type KeyMode string

const (
	KeyModeMaster   KeyMode = "master"
	KeyModePassword KeyMode = "password"
)

type Header struct {
	Magic       string  `json:"magic"`
	Version     int     `json:"version"`
	CreatedAt   string  `json:"createdAt"`
	SchemaVer   int     `json:"schemaVer"`
	KeyMode     KeyMode `json:"keyMode"`
	KDF         string  `json:"kdf"`
	KDFSaltB64  string  `json:"kdfSaltB64"`
	KDFTime     int     `json:"kdfTime"`
	KDFMemoryKB int     `json:"kdfMemoryKB"`
	KDFThreads  int     `json:"kdfThreads"`
	AEAD        string  `json:"aead"`
	NoncePrefB4 string  `json:"noncePrefB4"`
	Compression string  `json:"compression"`
	ChunkSize   int     `json:"chunkSize"`
}

type ExportOptions struct {
	KeyMode KeyMode
	Secret  string

	CreatedAt string
	ChunkSize int
}

func Export(ctx context.Context, db *sql.DB, w io.Writer, opts ExportOptions) error {
	if db == nil {
		return errors.New("backup: db is nil")
	}
	if w == nil {
		return errors.New("backup: writer is nil")
	}
	if opts.KeyMode != KeyModeMaster && opts.KeyMode != KeyModePassword {
		return errors.New("backup: invalid key mode")
	}
	if strings.TrimSpace(opts.Secret) == "" {
		return errors.New("backup: secret is empty")
	}

	chunkSize := opts.ChunkSize
	if chunkSize <= 0 {
		chunkSize = 64 << 10
	}
	if chunkSize < 4<<10 || chunkSize > 1<<20 {
		return errors.New("backup: chunk size out of range")
	}

	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	var schemaVer int
	_ = tx.QueryRowContext(ctx, "PRAGMA user_version;").Scan(&schemaVer)

	kdfSalt := make([]byte, 32)
	if _, err := rand.Read(kdfSalt); err != nil {
		return err
	}
	noncePref := make([]byte, 4)
	if _, err := rand.Read(noncePref); err != nil {
		return err
	}

	key := argon2.IDKey([]byte(opts.Secret), kdfSalt, 3, 32*1024, 2, 32)
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	h := Header{
		Magic:       fileMagic,
		Version:     fileVersion,
		CreatedAt:   strings.TrimSpace(opts.CreatedAt),
		SchemaVer:   schemaVer,
		KeyMode:     opts.KeyMode,
		KDF:         "argon2id",
		KDFSaltB64:  base64.StdEncoding.EncodeToString(kdfSalt),
		KDFTime:     3,
		KDFMemoryKB: 32 * 1024,
		KDFThreads:  2,
		AEAD:        "aes-256-gcm",
		NoncePrefB4: base64.StdEncoding.EncodeToString(noncePref),
		Compression: "gzip",
		ChunkSize:   chunkSize,
	}
	hdr, err := json.Marshal(h)
	if err != nil {
		return err
	}
	if len(hdr) == 0 || len(hdr) > 65535 {
		return errors.New("backup: header too large")
	}

	bw := bufio.NewWriter(w)
	if _, err := bw.WriteString(fileMagic); err != nil {
		return err
	}
	var u16 [2]byte
	binary.LittleEndian.PutUint16(u16[:], uint16(fileVersion))
	if _, err := bw.Write(u16[:]); err != nil {
		return err
	}
	binary.LittleEndian.PutUint16(u16[:], uint16(len(hdr)))
	if _, err := bw.Write(u16[:]); err != nil {
		return err
	}
	if _, err := bw.Write(hdr); err != nil {
		return err
	}

	ew := &frameEncryptWriter{
		w:          bw,
		aead:       gcm,
		aad:        hdr,
		noncePref4: noncePref,
		chunkSize:  chunkSize,
	}
	zw, err := gzip.NewWriterLevel(ew, gzip.BestSpeed)
	if err != nil {
		return err
	}

	bufw := bufio.NewWriterSize(zw, 64<<10)
	if _, err := bufw.WriteString(streamMagic); err != nil {
		return err
	}
	if err := exportAllTables(ctx, tx, bufw); err != nil {
		_ = zw.Close()
		return err
	}
	if err := bufw.Flush(); err != nil {
		_ = zw.Close()
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}
	if err := ew.Close(); err != nil {
		return err
	}
	if err := bw.Flush(); err != nil {
		return err
	}

	return tx.Commit()
}

type ImportOptions struct {
	Password  string
	MasterKey string
}

func Import(ctx context.Context, db *sql.DB, r io.Reader, opts ImportOptions) (Header, error) {
	if db == nil {
		return Header{}, errors.New("backup: db is nil")
	}
	if r == nil {
		return Header{}, errors.New("backup: reader is nil")
	}

	br := bufio.NewReader(r)
	magic := make([]byte, 4)
	if _, err := io.ReadFull(br, magic); err != nil {
		return Header{}, err
	}
	if string(magic) != fileMagic {
		return Header{}, errors.New("backup: bad magic")
	}

	var u16 [2]byte
	if _, err := io.ReadFull(br, u16[:]); err != nil {
		return Header{}, err
	}
	ver := int(binary.LittleEndian.Uint16(u16[:]))
	if ver != fileVersion {
		return Header{}, fmt.Errorf("backup: unsupported version: %d", ver)
	}
	if _, err := io.ReadFull(br, u16[:]); err != nil {
		return Header{}, err
	}
	hdrLen := int(binary.LittleEndian.Uint16(u16[:]))
	if hdrLen <= 0 || hdrLen > 65535 {
		return Header{}, errors.New("backup: bad header length")
	}
	hdr := make([]byte, hdrLen)
	if _, err := io.ReadFull(br, hdr); err != nil {
		return Header{}, err
	}

	var h Header
	if err := json.Unmarshal(hdr, &h); err != nil {
		return Header{}, errors.New("backup: invalid header json")
	}
	if strings.TrimSpace(h.Magic) != fileMagic || h.Version != fileVersion {
		return Header{}, errors.New("backup: invalid header")
	}
	if h.KDF != "argon2id" || h.AEAD != "aes-256-gcm" || h.Compression != "gzip" {
		return Header{}, errors.New("backup: unsupported params")
	}
	if h.KDFTime <= 0 || h.KDFTime > 10 || h.KDFMemoryKB <= 0 || h.KDFMemoryKB > 256*1024 || h.KDFThreads <= 0 || h.KDFThreads > 32 {
		return Header{}, errors.New("backup: invalid kdf params")
	}

	kdfSalt, err := base64.StdEncoding.DecodeString(strings.TrimSpace(h.KDFSaltB64))
	if err != nil || len(kdfSalt) != 32 {
		return Header{}, errors.New("backup: invalid kdf salt")
	}
	noncePref, err := base64.StdEncoding.DecodeString(strings.TrimSpace(h.NoncePrefB4))
	if err != nil || len(noncePref) != 4 {
		return Header{}, errors.New("backup: invalid nonce prefix")
	}

	secret := ""
	switch h.KeyMode {
	case KeyModeMaster:
		secret = opts.MasterKey
	case KeyModePassword:
		secret = opts.Password
	default:
		return Header{}, errors.New("backup: unsupported key mode")
	}
	if strings.TrimSpace(secret) == "" {
		return Header{}, errors.New("backup: secret is required")
	}

	key := argon2.IDKey([]byte(secret), kdfSalt, uint32(h.KDFTime), uint32(h.KDFMemoryKB), uint8(h.KDFThreads), 32)
	block, err := aes.NewCipher(key)
	if err != nil {
		return Header{}, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return Header{}, err
	}

	dr := &frameDecryptReader{
		r:          br,
		aead:       gcm,
		aad:        hdr,
		noncePref4: noncePref,
		maxFrame:   4<<20 + gcm.Overhead(),
	}
	zr, err := gzip.NewReader(dr)
	if err != nil {
		return Header{}, err
	}
	defer func() { _ = zr.Close() }()

	bufr := bufio.NewReaderSize(zr, 64<<10)
	sm := make([]byte, 4)
	if _, err := io.ReadFull(bufr, sm); err != nil {
		return Header{}, err
	}
	if string(sm) != streamMagic {
		return Header{}, errors.New("backup: invalid payload")
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return Header{}, err
	}
	defer func() { _ = tx.Rollback() }()

	if err := clearAll(tx, ctx); err != nil {
		return Header{}, err
	}

	usersCount, hasConfigCurrent, err := importAllTables(ctx, tx, bufr)
	if err != nil {
		return Header{}, err
	}
	if usersCount <= 0 {
		return Header{}, errors.New("backup: no users in backup")
	}
	if !hasConfigCurrent {
		return Header{}, errors.New("backup: missing config_current")
	}
	if err := verifyConfigDecryptable(ctx, tx, strings.TrimSpace(opts.MasterKey)); err != nil {
		return Header{}, err
	}

	if err := tx.Commit(); err != nil {
		return Header{}, err
	}
	return h, nil
}

func verifyConfigDecryptable(ctx context.Context, tx *sql.Tx, masterKey string) error {
	var configJSON string
	if err := tx.QueryRowContext(ctx, "SELECT config_json FROM config_current WHERE id = 1;").Scan(&configJSON); err != nil {
		return err
	}

	var saltB64 string
	_ = tx.QueryRowContext(ctx, "SELECT value FROM meta WHERE key = ?;", "kdf_salt_b64").Scan(&saltB64)
	saltB64 = strings.TrimSpace(saltB64)
	if saltB64 == "" {
		return errors.New("backup: missing kdf salt")
	}

	crypto, err := storage.NewCryptoContextFromSalt(masterKey, saltB64)
	if err != nil {
		return err
	}

	plainJSON, err := crypto.DecryptString(strings.TrimSpace(configJSON))
	if err != nil {
		return err
	}
	if !strings.Contains(plainJSON, "enc:v1:") {
		return nil
	}

	var cfg model.AppConfig
	if err := json.Unmarshal([]byte(plainJSON), &cfg); err != nil {
		return err
	}

	try := func(v string) error {
		if strings.TrimSpace(v) == "" {
			return nil
		}
		_, err := crypto.DecryptString(v)
		return err
	}

	if err := try(cfg.Git.GithubToken); err != nil {
		return err
	}
	for _, inst := range cfg.GitInstances {
		if err := try(inst.Git.GithubToken); err != nil {
			return err
		}
	}
	if err := try(cfg.Torcherino.WorkerSecretKey); err != nil {
		return err
	}
	if err := try(cfg.Sakuya.Oplist.Token); err != nil {
		return err
	}
	for _, inst := range cfg.Sakuya.Instances {
		if err := try(inst.Token); err != nil {
			return err
		}
	}
	for _, v := range cfg.Torcherino.WorkerSecretHeaderMap {
		if err := try(v); err != nil {
			return err
		}
	}

	return nil
}

func clearAll(tx *sql.Tx, ctx context.Context) error {
	deleteOrder := []string{
		"sessions",
		"config_versions",
		"config_current",
		"traffic_buckets",
		"traffic_totals",
		"users",
		"meta",
	}
	for _, tbl := range deleteOrder {
		_, _ = tx.ExecContext(ctx, "DELETE FROM "+sqliteIdent(tbl)+";")
	}
	return nil
}

func sqliteIdent(name string) string {
	return `"` + strings.ReplaceAll(name, `"`, `""`) + `"`
}

type frameEncryptWriter struct {
	w          io.Writer
	aead       cipher.AEAD
	aad        []byte
	noncePref4 []byte
	chunkSize  int
	counter    uint64
	buf        []byte
}

func (w *frameEncryptWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	w.buf = append(w.buf, p...)
	for len(w.buf) >= w.chunkSize {
		if err := w.flush(w.buf[:w.chunkSize]); err != nil {
			return 0, err
		}
		copy(w.buf, w.buf[w.chunkSize:])
		w.buf = w.buf[:len(w.buf)-w.chunkSize]
	}
	return len(p), nil
}

func (w *frameEncryptWriter) Close() error {
	if len(w.buf) > 0 {
		if err := w.flush(w.buf); err != nil {
			return err
		}
		w.buf = nil
	}
	return nil
}

func (w *frameEncryptWriter) flush(plain []byte) error {
	nonce := make([]byte, w.aead.NonceSize())
	copy(nonce, w.noncePref4)
	binary.BigEndian.PutUint64(nonce[len(w.noncePref4):], w.counter)
	w.counter++

	ct := w.aead.Seal(nil, nonce, plain, w.aad)
	if len(ct) > int(^uint32(0)) {
		return errors.New("backup: frame too large")
	}
	var u32 [4]byte
	binary.LittleEndian.PutUint32(u32[:], uint32(len(ct)))
	if _, err := w.w.Write(u32[:]); err != nil {
		return err
	}
	_, err := w.w.Write(ct)
	return err
}

type frameDecryptReader struct {
	r          io.Reader
	aead       cipher.AEAD
	aad        []byte
	noncePref4 []byte
	counter    uint64

	maxFrame int

	buf []byte
}

func (r *frameDecryptReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if len(r.buf) == 0 {
		var u32 [4]byte
		_, err := io.ReadFull(r.r, u32[:])
		if err != nil {
			return 0, err
		}
		n := int(binary.LittleEndian.Uint32(u32[:]))
		if n <= 0 || (r.maxFrame > 0 && n > r.maxFrame) {
			return 0, errors.New("backup: invalid frame size")
		}
		ct := make([]byte, n)
		if _, err := io.ReadFull(r.r, ct); err != nil {
			return 0, err
		}

		nonce := make([]byte, r.aead.NonceSize())
		copy(nonce, r.noncePref4)
		binary.BigEndian.PutUint64(nonce[len(r.noncePref4):], r.counter)
		r.counter++

		pt, err := r.aead.Open(nil, nonce, ct, r.aad)
		if err != nil {
			return 0, err
		}
		r.buf = pt
	}

	n := copy(p, r.buf)
	r.buf = r.buf[n:]
	return n, nil
}

func exportAllTables(ctx context.Context, tx *sql.Tx, w io.Writer) error {
	if err := exportTable(ctx, tx, w, "meta", "SELECT key, value FROM meta ORDER BY key;"); err != nil {
		return err
	}
	if err := exportTable(ctx, tx, w, "users", "SELECT id, username, password_hash, created_at, updated_at FROM users ORDER BY id;"); err != nil {
		return err
	}
	if err := exportTable(ctx, tx, w, "config_current", "SELECT id, config_json, updated_at, updated_by FROM config_current ORDER BY id;"); err != nil {
		return err
	}
	if err := exportTable(ctx, tx, w, "config_versions", "SELECT id, config_json, created_at, created_by, note FROM config_versions ORDER BY id;"); err != nil {
		return err
	}
	if err := exportTable(ctx, tx, w, "sessions", "SELECT token_hash, user_id, created_at, expires_at FROM sessions ORDER BY token_hash;"); err != nil {
		return err
	}
	if err := exportTableOptional(ctx, tx, w, "traffic_totals", "SELECT service, bytes_in, bytes_out, requests, updated_at FROM traffic_totals ORDER BY service;"); err != nil {
		return err
	}
	if err := exportTableOptional(ctx, tx, w, "traffic_buckets", "SELECT kind, start_ts, service, bytes_in, bytes_out, requests, updated_at FROM traffic_buckets ORDER BY kind, start_ts, service;"); err != nil {
		return err
	}
	return writeByte(w, recEnd)
}

func exportTableOptional(ctx context.Context, tx *sql.Tx, w io.Writer, name string, query string) error {
	var found string
	err := tx.QueryRowContext(ctx, "SELECT name FROM sqlite_master WHERE type='table' AND name = ?;", name).Scan(&found)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		return err
	}
	if strings.TrimSpace(found) == "" {
		return nil
	}
	return exportTable(ctx, tx, w, name, query)
}

func exportTable(ctx context.Context, tx *sql.Tx, w io.Writer, name string, query string) error {
	rows, err := tx.QueryContext(ctx, query)
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()

	cols, err := rows.Columns()
	if err != nil {
		return err
	}

	if err := writeByte(w, recTableStart); err != nil {
		return err
	}
	if err := writeString(w, name); err != nil {
		return err
	}
	if err := writeUvarint(w, uint64(len(cols))); err != nil {
		return err
	}
	for _, c := range cols {
		if err := writeString(w, c); err != nil {
			return err
		}
	}

	values := make([]any, len(cols))
	ptrs := make([]any, len(cols))
	for i := range values {
		ptrs[i] = &values[i]
	}
	for rows.Next() {
		clear(values)
		if err := rows.Scan(ptrs...); err != nil {
			return err
		}
		if err := writeByte(w, recRow); err != nil {
			return err
		}
		if err := writeUvarint(w, uint64(len(values))); err != nil {
			return err
		}
		for _, v := range values {
			if err := writeValue(w, v); err != nil {
				return err
			}
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}

	if err := writeByte(w, recTableEnd); err != nil {
		return err
	}
	return writeString(w, name)
}

const (
	recEnd        = 0
	recTableStart = 1
	recRow        = 2
	recTableEnd   = 3

	valNull   = 0
	valInt    = 1
	valFloat  = 2
	valBytes  = 3
	valString = 4
)

func writeByte(w io.Writer, b byte) error {
	var buf [1]byte
	buf[0] = b
	_, err := w.Write(buf[:])
	return err
}

func writeUvarint(w io.Writer, x uint64) error {
	var buf [10]byte
	n := binary.PutUvarint(buf[:], x)
	_, err := w.Write(buf[:n])
	return err
}

func writeVarint(w io.Writer, x int64) error {
	var buf [10]byte
	n := binary.PutVarint(buf[:], x)
	_, err := w.Write(buf[:n])
	return err
}

func writeBytes(w io.Writer, b []byte) error {
	if err := writeUvarint(w, uint64(len(b))); err != nil {
		return err
	}
	_, err := w.Write(b)
	return err
}

func writeString(w io.Writer, s string) error {
	return writeBytes(w, []byte(s))
}

func writeValue(w io.Writer, v any) error {
	switch x := v.(type) {
	case nil:
		return writeByte(w, valNull)
	case int64:
		if err := writeByte(w, valInt); err != nil {
			return err
		}
		return writeVarint(w, x)
	case float64:
		if err := writeByte(w, valFloat); err != nil {
			return err
		}
		var buf [8]byte
		binary.LittleEndian.PutUint64(buf[:], math.Float64bits(x))
		_, err := w.Write(buf[:])
		return err
	case []byte:
		if err := writeByte(w, valBytes); err != nil {
			return err
		}
		return writeBytes(w, x)
	case string:
		if err := writeByte(w, valString); err != nil {
			return err
		}
		return writeString(w, x)
	case int:
		if err := writeByte(w, valInt); err != nil {
			return err
		}
		return writeVarint(w, int64(x))
	case int32:
		if err := writeByte(w, valInt); err != nil {
			return err
		}
		return writeVarint(w, int64(x))
	case int16:
		if err := writeByte(w, valInt); err != nil {
			return err
		}
		return writeVarint(w, int64(x))
	case int8:
		if err := writeByte(w, valInt); err != nil {
			return err
		}
		return writeVarint(w, int64(x))
	case uint64:
		if err := writeByte(w, valInt); err != nil {
			return err
		}
		if x > uint64(math.MaxInt64) {
			return errors.New("backup: uint64 too large")
		}
		return writeVarint(w, int64(x))
	case uint32:
		if err := writeByte(w, valInt); err != nil {
			return err
		}
		return writeVarint(w, int64(x))
	case uint16:
		if err := writeByte(w, valInt); err != nil {
			return err
		}
		return writeVarint(w, int64(x))
	case uint8:
		if err := writeByte(w, valInt); err != nil {
			return err
		}
		return writeVarint(w, int64(x))
	default:
		return errors.New("backup: unsupported value type")
	}
}

func importAllTables(ctx context.Context, tx *sql.Tx, r *bufio.Reader) (usersCount int64, hasConfigCurrent bool, err error) {
	curTable := ""
	curCols := []string(nil)
	var ins *sql.Stmt
	defer func() { _ = closeStmt(ins) }()

	for {
		t, err := r.ReadByte()
		if err != nil {
			return usersCount, hasConfigCurrent, err
		}
		switch t {
		case recEnd:
			return usersCount, hasConfigCurrent, nil
		case recTableStart:
			name, cols, err := readTableStart(r)
			if err != nil {
				return usersCount, hasConfigCurrent, err
			}
			if curTable != "" {
				return usersCount, hasConfigCurrent, errors.New("backup: nested table")
			}
			if !isAllowedTable(name, cols) {
				return usersCount, hasConfigCurrent, errors.New("backup: unsupported table schema")
			}
			curTable = name
			curCols = cols
			ins, err = prepareInsert(ctx, tx, name, cols)
			if err != nil {
				return usersCount, hasConfigCurrent, err
			}
		case recRow:
			if curTable == "" || ins == nil {
				return usersCount, hasConfigCurrent, errors.New("backup: row outside table")
			}
			vals, err := readRowValues(r, len(curCols))
			if err != nil {
				return usersCount, hasConfigCurrent, err
			}
			if _, err := ins.ExecContext(ctx, vals...); err != nil {
				return usersCount, hasConfigCurrent, err
			}
			if curTable == "users" {
				usersCount++
			}
			if curTable == "config_current" {
				hasConfigCurrent = true
			}
		case recTableEnd:
			name, err := readString(r)
			if err != nil {
				return usersCount, hasConfigCurrent, err
			}
			if name != curTable {
				return usersCount, hasConfigCurrent, errors.New("backup: table end mismatch")
			}
			_ = closeStmt(ins)
			ins = nil
			curTable = ""
			curCols = nil
		default:
			return usersCount, hasConfigCurrent, errors.New("backup: unknown record type")
		}
	}
}

func closeStmt(st *sql.Stmt) error {
	if st == nil {
		return nil
	}
	return st.Close()
}

func readTableStart(r *bufio.Reader) (string, []string, error) {
	name, err := readString(r)
	if err != nil {
		return "", nil, err
	}
	nColsU, err := binary.ReadUvarint(r)
	if err != nil {
		return "", nil, err
	}
	if nColsU > 128 {
		return "", nil, errors.New("backup: too many columns")
	}
	cols := make([]string, 0, int(nColsU))
	for i := 0; i < int(nColsU); i++ {
		c, err := readString(r)
		if err != nil {
			return "", nil, err
		}
		cols = append(cols, c)
	}
	return name, cols, nil
}

func readRowValues(r *bufio.Reader, want int) ([]any, error) {
	nU, err := binary.ReadUvarint(r)
	if err != nil {
		return nil, err
	}
	if int(nU) != want {
		return nil, errors.New("backup: column count mismatch")
	}
	out := make([]any, 0, want)
	for i := 0; i < want; i++ {
		k, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		switch k {
		case valNull:
			out = append(out, nil)
		case valInt:
			v, err := binary.ReadVarint(r)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		case valFloat:
			var buf [8]byte
			if _, err := io.ReadFull(r, buf[:]); err != nil {
				return nil, err
			}
			out = append(out, math.Float64frombits(binary.LittleEndian.Uint64(buf[:])))
		case valBytes:
			b, err := readBytes(r)
			if err != nil {
				return nil, err
			}
			out = append(out, b)
		case valString:
			s, err := readString(r)
			if err != nil {
				return nil, err
			}
			out = append(out, s)
		default:
			return nil, errors.New("backup: unknown value type")
		}
	}
	return out, nil
}

func readBytes(r *bufio.Reader) ([]byte, error) {
	n, err := binary.ReadUvarint(r)
	if err != nil {
		return nil, err
	}
	if n > 512<<20 {
		return nil, errors.New("backup: value too large")
	}
	b := make([]byte, int(n))
	_, err = io.ReadFull(r, b)
	return b, err
}

func readString(r *bufio.Reader) (string, error) {
	b, err := readBytes(r)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func isAllowedTable(name string, cols []string) bool {
	want, ok := allowedTables[name]
	if !ok {
		return false
	}
	if len(cols) != len(want) {
		return false
	}
	for i := range cols {
		if cols[i] != want[i] {
			return false
		}
	}
	return true
}

var allowedTables = map[string][]string{
	"meta":            {"key", "value"},
	"users":           {"id", "username", "password_hash", "created_at", "updated_at"},
	"config_current":  {"id", "config_json", "updated_at", "updated_by"},
	"config_versions": {"id", "config_json", "created_at", "created_by", "note"},
	"sessions":        {"token_hash", "user_id", "created_at", "expires_at"},
	"traffic_totals":  {"service", "bytes_in", "bytes_out", "requests", "updated_at"},
	"traffic_buckets": {"kind", "start_ts", "service", "bytes_in", "bytes_out", "requests", "updated_at"},
}

func prepareInsert(ctx context.Context, tx *sql.Tx, table string, cols []string) (*sql.Stmt, error) {
	var b strings.Builder
	b.WriteString("INSERT INTO ")
	b.WriteString(sqliteIdent(table))
	b.WriteString(" (")
	for i, c := range cols {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(sqliteIdent(c))
	}
	b.WriteString(") VALUES (")
	for i := range cols {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString("?")
	}
	b.WriteString(");")
	return tx.PrepareContext(ctx, b.String())
}
