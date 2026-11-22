package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	_ "modernc.org/sqlite"
)

const DBPath string = "data/logoracle.db"

const (
	EMERG byte = iota
	ALERT
	CRIT
	ERR
	WARNING
	NOTICE
	INFO
	DEBUG
)

type JournaldRaw map[string]json.RawMessage
type JournaldLog = JournaldRaw
type JournaldBootEntry = JournaldRaw

func (j JournaldRaw) GetValue[T any](key string) T {
	var value T

	raw, exists := j[key]
	if !exists {
		return value
	}

	if err := json.Unmarshal(raw, &value); err != nil {
		return value
	}
	return value
}

type Event struct {
	Timestamp   time.Time
	Host        string
	Application *Application
	Severity    byte
	Message     string
	Boot        *BootEntry
	PID         int64
	Cursor      string
}

type Application struct {
	ID   int64
	Name string
}

type BootEntry struct {
	ID       int64
	GUID     string
	TimeFrom time.Time
	TimeTo   time.Time
}

type UnitOfWork struct {
	Events       []Event
	Applications []*Application
	BootEntries  []*BootEntry
	LastCursor   string
	Provider     string
}

type InputBatch struct {
	Logs  []JournaldLog
	Boots []JournaldBootEntry
}

type Store struct {
	db *sql.DB
}

type PipelineCtx struct {
	store    *Store
	provider string
}

type SQLQuery struct {
	Select  string
	From    string
	Where   string
	OrderBy string
	Limit   string
}

func main() {
	if err := runJournaldPipeline(); err != nil {
		log.Fatal(err)
	}
}

func runJournaldPipeline() error {
	if err := os.MkdirAll(filepath.Dir(DBPath), 0755); err != nil {
		return fmt.Errorf("ERROR: creating database directory: %w", err)
	}

	db, err := OpenDatabase(DBPath)
	if err != nil {
		return err
	}
	defer func() {
		_ = db.Close()
	}()

	if err := createSchemaIfNotExists(db); err != nil {
		return fmt.Errorf("ERROR: initializing database schema: %w", err)
	}

	ctx := &PipelineCtx{
		store:    &Store{db: db},
		provider: "journald",
	}

	cursor, err := ctx.getIngestionState()
	if err != nil {
		return err
	}

	batch, err := extractJournald(cursor)
	if err != nil {
		return err
	}

	unitOfWork, err := normalizeJournaldLogs(batch)
	if err != nil {
		return err
	}

	unitOfWork.Provider = ctx.provider

	if err := ctx.store.persistBatch(unitOfWork); err != nil {
		return err
	}

	return nil
}

func (c *PipelineCtx) getIngestionState() (string, error) {
	cursorSlice, err := c.store.ReadTableRows(
		SQLQuery{
			Select:  "last_cursor",
			From:    "ingestion_state",
			Where:   "",
			OrderBy: "updated_at",
			Limit:   "1",
		},
		func(rows *sql.Rows) (string, error) {
			var cursor string

			if err := rows.Scan(&cursor); err != nil {
				return "", err
			}

			return cursor, nil
		},
	)
	if err != nil {
		return "", err
	}
	if len(cursorSlice) < 1 || cursorSlice[0] == "" {
		return "", err
	}

	return cursorSlice[0], nil
}

func extractJournald(cursor string) (InputBatch, error) {
	var (
		cmd   *exec.Cmd
		batch InputBatch
	)

	args := []string{"-o", "json", "--no-pager"}
	if cursor != "" {
		args = append(args, "--after-cursor="+cursor)
	}

	cmd = exec.Command("journalctl", args...)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return batch, err
	}

	if err := cmd.Start(); err != nil {
		return batch, err
	}

	decoder := json.NewDecoder(stdout)

	for {
		var entry JournaldLog
		err := decoder.Decode(&entry)

		if errors.Is(err, io.EOF) {
			break
		}

		if err != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			return batch, err
		}

		batch.Logs = append(batch.Logs, entry)
	}

	if err := cmd.Wait(); err != nil {
		return batch, err
	}

	args = []string{"--list-boots", "-o", "json", "--no-pager"}

	cmd = exec.Command("journalctl", args...)

	stdout, err = cmd.StdoutPipe()
	if err != nil {
		return batch, err
	}

	if err := cmd.Start(); err != nil {
		return batch, err
	}

	decoder = json.NewDecoder(stdout)

	var entries []JournaldBootEntry
	if err := decoder.Decode(&entries); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return batch, err
	}

	if err := cmd.Wait(); err != nil {
		return batch, err
	}

	batch.Boots = entries
	return batch, nil
}

func normalizeJournaldLogs(batch InputBatch) (UnitOfWork, error) {
	var (
		applications map[string]*Application
		boots        map[string]*BootEntry
		unitOfWork   UnitOfWork
	)
	applications = make(map[string]*Application)
	boots = make(map[string]*BootEntry)
	for i, boot := range batch.Boots {
		key := boot.GetValue[string]("boot_id")
		if key == "" {
			return unitOfWork, fmt.Errorf("ERROR: boot entry %d doesn't exist", i)
		}

		microseconds := boot.GetValue[int64]("first_entry")
		if microseconds == 0 {
			return unitOfWork, fmt.Errorf("ERROR: boot entry %d's time_from is invalid", i)
		}
		timeFrom := time.UnixMicro(microseconds).UTC()

		microseconds = boot.GetValue[int64]("last_entry")
		if microseconds == 0 {
			return unitOfWork, fmt.Errorf("ERROR: boot entry %d's time_to is invalid", i)
		}
		timeTo := time.UnixMicro(microseconds).UTC()

		value := &BootEntry{
			GUID:     key,
			TimeFrom: timeFrom,
			TimeTo:   timeTo,
		}
		boots[key] = value
		unitOfWork.BootEntries = append(unitOfWork.BootEntries, value)
	}

	for i, log := range batch.Logs {
		appName := log.GetValue[string]("SYSLOG_IDENTIFIER")
		if appName == "" {
			appName = log.GetValue[string]("_COMM")
		}
		if appName == "" {
			appName = "unknown"
		}

		app := applications[appName]
		if app == nil {
			app = &Application{Name: appName}
			applications[appName] = app
			unitOfWork.Applications = append(unitOfWork.Applications, app)
		}

		bootGUID := log.GetValue[string]("_BOOT_ID")
		if bootGUID == "" {
			return unitOfWork, fmt.Errorf("ERROR: Log entry %d missing boot GUID", i)
		}
		boot := boots[bootGUID]

		// if boot == nil {
		// 	boot = &BootEntry{
		// 		GUID: bootGUID,
		// 	}
		// 	boots[bootGUID] = boot
		//	unitOfWork.BootEntries = append(unitOfWork.BootEntries, boot)
		// }

		timestampStr := log.GetValue[string]("__REALTIME_TIMESTAMP")
		microseconds, err := strconv.ParseInt(timestampStr, 10, 64)
		if err != nil {
			return unitOfWork,
				fmt.Errorf("ERROR: Log entry %d features invalid timestamp %q - %w",
					i, timestampStr, err)
		}
		timestamp := time.UnixMicro(microseconds).UTC()

		severityStr := log.GetValue[string]("PRIORITY")
		severity := byte(255)
		if severityStr != "" {
			value, err := strconv.ParseUint(severityStr, 10, 8)
			if err == nil && value <= 7 {
				severity = byte(value)
			}
		}

		cursor := log.GetValue[string]("__CURSOR")
		if cursor == "" {
			return unitOfWork, fmt.Errorf("ERROR: Log entry %d missing journald cursor", i)
		}

		pidStr := log.GetValue[string]("_PID")
		if pidStr == "" {
			return unitOfWork, fmt.Errorf("ERROR: Log entry %d missing PID", i)
		}
		pid, err := strconv.ParseInt(pidStr, 10, 64)
		if err != nil {
			return unitOfWork, fmt.Errorf("ERROR: Log entry %d's cannot be converted", i)
		}

		event := Event{
			Timestamp:   timestamp,
			Host:        log.GetValue[string]("_HOSTNAME"),
			Application: app,
			Severity:    severity,
			Message:     log.GetValue[string]("MESSAGE"),
			Boot:        boot,
			PID:         pid,
			Cursor:      cursor,
		}
		unitOfWork.Events = append(unitOfWork.Events, event)
		unitOfWork.LastCursor = event.Cursor
	}

	return unitOfWork, nil
}

func (s *Store) persistBatch(unitOfwork UnitOfWork) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	for _, app := range unitOfwork.Applications {
		if err := persistApplication(tx, app); err != nil {
			return err
		}
	}

	for _, boot := range unitOfwork.BootEntries {
		if err := persistBoot(tx, boot); err != nil {
			return err
		}
	}

	for _, event := range unitOfwork.Events {
		if err := persistEvent(tx, event); err != nil {
			return err
		}
	}

	cursor := unitOfwork.LastCursor
	source := unitOfwork.Provider

	if unitOfwork.LastCursor != "" {
		if err := persistIngestionState(tx, source, cursor); err != nil {
			return err
		}
	}

	return tx.Commit()
}

func persistApplication(tx *sql.Tx, app *Application) error {
	_, err := tx.Exec(`
			INSERT INTO applications (name)
			VALUES (?)
			ON CONFLICT(name) DO NOTHING
		`, app.Name)
	if err != nil {
		return err
	}

	return tx.QueryRow(`
			SELECT id FROM applications WHERE name = ?
		`, app.Name).Scan(&app.ID)
}

func persistBoot(tx *sql.Tx, boot *BootEntry) error {
	_, err := tx.Exec(`
			INSERT INTO boots (guid, time_from, time_to)
			VALUES (?, ?, ?)
			ON CONFLICT(guid) DO UPDATE SET
				time_from = excluded.time_from,
				time_to   = excluded.time_to
			`,
		boot.GUID,
		boot.TimeFrom.UnixMicro(),
		boot.TimeTo.UnixMicro(),
	)
	if err != nil {
		return fmt.Errorf("ERROR: persisting boot %s: %w", boot.GUID, err)
	}

	return tx.QueryRow(`
			SELECT id FROM boots WHERE guid = ?
		`, boot.GUID).Scan(&boot.ID)
}

func persistEvent(tx *sql.Tx, event Event) error {
	_, err := tx.Exec(`
			INSERT INTO events (
				timestamp,
				host,
				application_id,
				severity,
				message,
				boot_id,
				pid,
				cursor
			)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(cursor) DO NOTHING
		`,
		event.Timestamp.UnixMicro(),
		event.Host,
		event.Application.ID,
		event.Severity,
		event.Message,
		event.Boot.ID,
		event.PID,
		event.Cursor,
	)
	if err != nil {
		return err
	}

	return nil
}

func persistIngestionState(tx *sql.Tx, source string, cursor string) error {
	_, err := tx.Exec(`
			INSERT INTO ingestion_state (
				source,
				last_cursor,
				updated_at
			)
			VALUES (?, ?, ?)
			ON CONFLICT (source) DO UPDATE SET
				last_cursor = excluded.last_cursor,
				updated_at  = excluded.updated_at
		`, source, cursor, time.Now().UnixMicro())

	if err != nil {
		return err
	}

	return nil
}

func OpenDatabase(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}

	db.SetMaxOpenConns(1)

	if _, err := db.Exec("PRAGMA foreign_keys = ON"); err != nil {
		func() {
			_ = db.Close()
		}()
		return nil, err
	}

	if err := db.Ping(); err != nil {
		func() {
			_ = db.Close()
		}()
		return nil, err
	}

	return db, nil
}

func createSchemaIfNotExists(db *sql.DB) error {
	_, err := db.Exec(`
			CREATE TABLE IF NOT EXISTS ingestion_state (
				source      TEXT PRIMARY KEY,
				last_cursor TEXT NOT NULL,
				updated_at  INTEGER NOT NULL
			);

		`)
	if err != nil {
		return err
	}

	_, err = db.Exec(`
			CREATE TABLE IF NOT EXISTS applications (
				id   INTEGER PRIMARY KEY,
				name TEXT NOT NULL UNIQUE
			);

		`)
	if err != nil {
		return err
	}

	_, err = db.Exec(`
			CREATE TABLE IF NOT EXISTS boots (
				id          INTEGER PRIMARY KEY,
				guid        TEXT NOT NULL UNIQUE,
				time_from   INTEGER,
				time_to     INTEGER
			);

		`)
	if err != nil {
		return err
	}

	_, err = db.Exec(`
			CREATE TABLE IF NOT EXISTS events (
				id             INTEGER PRIMARY KEY,
				timestamp      INTEGER NOT NULL,
				host           TEXT,
				application_id INTEGER,
				severity       INTEGER,
				message        TEXT,
				boot_id        INTEGER NOT NULL,
				pid            INTEGER NOT NULL,
				cursor         TEXT NOT NULL UNIQUE,

				FOREIGN KEY (application_id)
					REFERENCES applications(id),
				FOREIGN KEY (boot_id)
					REFERENCES boots(id)
			);
						
		`)
	if err != nil {
		return err
	}

	return nil
}

func (s *Store) ReadTableRows[T any](query SQLQuery, decode func(*sql.Rows) (T, error)) ([]T, error) {
	queryString := fmt.Sprintf(`
			SELECT   %s
			FROM     %s
		`, query.Select, query.From)
	if query.Where != "" {
		queryString = fmt.Sprintf("%s WHERE %s", queryString, query.Where)
	}
	if query.OrderBy != "" {
		queryString = fmt.Sprintf("%s ORDER BY %s", queryString, query.OrderBy)
	}
	if query.Limit != "" {
		queryString = fmt.Sprintf("%s LIMIT %s", queryString, query.Limit)
	}

	rows, err := s.db.Query(queryString)
	if err != nil {
		return nil, err
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}

	defer func() {
		_ = rows.Close()
	}()

	var result []T
	for rows.Next() {
		value, err := decode(rows)
		if err != nil {
			return nil, err
		}

		result = append(result, value)
	}
	return result, nil
}
