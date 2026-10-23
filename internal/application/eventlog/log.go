// Package eventlog provides append-only event logs with stable cursors.
package eventlog

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/KLORQ/quarshell-core/domain"
)

// ErrCursorLost means the cursor points before the retained history.
var ErrCursorLost = errors.New("event cursor is no longer retained")

// Event is one durable stream event.
type Event struct {
	ID      uint64    `json:"id"`
	Stream  string    `json:"stream"`
	Kind    string    `json:"kind"`
	Payload []byte    `json:"payload,omitempty"`
	At      time.Time `json:"at"`
}

// Cursor is an opaque position. Empty means "from the beginning".
type Cursor string

// Log is an append-only event store.
type Log interface {
	Append(context.Context, string, string, []byte) (Cursor, error)
	After(context.Context, Cursor, int) ([]Event, Cursor, error)
	Latest(context.Context) (Cursor, error)
}

// MemoryLog is a bounded in-memory event log.
type MemoryLog struct {
	mu        sync.Mutex
	retention int
	next      uint64
	events    []Event
	now       func() time.Time
}

// NewMemoryLog returns a log retaining at most retention events.
func NewMemoryLog(retention int) *MemoryLog {
	if retention <= 0 {
		retention = 1000
	}
	return &MemoryLog{retention: retention, now: time.Now}
}

// Append records one event.
func (l *MemoryLog) Append(ctx context.Context, stream, kind string, payload []byte) (Cursor, error) {
	if err := ctx.Err(); err != nil {
		return "", domain.Wrap(domain.ErrCanceled, "eventlog.append", "append canceled")
	}
	if stream == "" || kind == "" {
		return "", domain.Invalidf("eventlog.append", "stream and kind are required")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.next++
	event := Event{ID: l.next, Stream: stream, Kind: kind, Payload: append([]byte(nil), payload...), At: l.now()}
	l.events = append(l.events, event)
	if len(l.events) > l.retention {
		l.events = l.events[len(l.events)-l.retention:]
	}
	return Cursor(strconv.FormatUint(event.ID, 10)), nil
}

// After returns events after cursor.
func (l *MemoryLog) After(ctx context.Context, cursor Cursor, limit int) ([]Event, Cursor, error) {
	if err := ctx.Err(); err != nil {
		return nil, "", domain.Wrap(domain.ErrCanceled, "eventlog.after", "read canceled")
	}
	position, err := parseCursor(cursor)
	if err != nil {
		return nil, "", err
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if cursor != "" && len(l.events) > 0 && position+1 < l.events[0].ID {
		return nil, "", domain.Wrap(ErrCursorLost, "eventlog.after", "cursor is no longer retained")
	}
	result := make([]Event, 0, limit)
	next := cursor
	for _, event := range l.events {
		if event.ID <= position {
			continue
		}
		result = append(result, cloneEvent(event))
		next = Cursor(strconv.FormatUint(event.ID, 10))
		if len(result) >= limit {
			break
		}
	}
	return result, next, nil
}

// Latest returns the newest cursor.
func (l *MemoryLog) Latest(context.Context) (Cursor, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.next == 0 {
		return "", nil
	}
	return Cursor(strconv.FormatUint(l.next, 10)), nil
}

// FileLog is an append-only JSONL event log. It fsyncs each append.
type FileLog struct {
	mu    sync.Mutex
	path  string
	file  *os.File
	next  uint64
	first uint64
	now   func() time.Time
}

// NewFileLog opens or creates a durable log.
func NewFileLog(path string) (*FileLog, error) {
	if path == "" {
		return nil, domain.Invalidf("eventlog.file", "path is required")
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return nil, domain.Wrap(err, "eventlog.file", "open log")
	}
	log := &FileLog{path: path, file: file, now: time.Now}
	if err := log.load(); err != nil {
		_ = file.Close()
		return nil, err
	}
	return log, nil
}

func (l *FileLog) load() error {
	if _, err := l.file.Seek(0, 0); err != nil {
		return domain.Wrap(err, "eventlog.file", "seek log")
	}
	scanner := bufio.NewScanner(l.file)
	scanner.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for scanner.Scan() {
		var event Event
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			return domain.Wrap(err, "eventlog.file", "decode log entry")
		}
		if l.first == 0 {
			l.first = event.ID
		}
		if event.ID > l.next {
			l.next = event.ID
		}
	}
	if err := scanner.Err(); err != nil {
		return domain.Wrap(err, "eventlog.file", "scan log")
	}
	_, err := l.file.Seek(0, 2)
	return err
}

// Append writes and fsyncs one event.
func (l *FileLog) Append(ctx context.Context, stream, kind string, payload []byte) (Cursor, error) {
	if err := ctx.Err(); err != nil {
		return "", domain.Wrap(domain.ErrCanceled, "eventlog.append", "append canceled")
	}
	if stream == "" || kind == "" {
		return "", domain.Invalidf("eventlog.append", "stream and kind are required")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.next++
	event := Event{ID: l.next, Stream: stream, Kind: kind, Payload: append([]byte(nil), payload...), At: l.now()}
	encoded, err := json.Marshal(event)
	if err != nil {
		return "", domain.Wrap(err, "eventlog.append", "encode event")
	}
	encoded = append(encoded, '\n')
	if _, err := l.file.Write(encoded); err != nil {
		return "", domain.Wrap(err, "eventlog.append", "write event")
	}
	if err := l.file.Sync(); err != nil {
		return "", domain.Wrap(err, "eventlog.append", "sync event")
	}
	if l.first == 0 {
		l.first = event.ID
	}
	return Cursor(strconv.FormatUint(event.ID, 10)), nil
}

// After reads events after cursor from the file.
func (l *FileLog) After(ctx context.Context, cursor Cursor, limit int) ([]Event, Cursor, error) {
	if err := ctx.Err(); err != nil {
		return nil, "", domain.Wrap(domain.ErrCanceled, "eventlog.after", "read canceled")
	}
	position, err := parseCursor(cursor)
	if err != nil {
		return nil, "", err
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if cursor != "" && l.first > 0 && position+1 < l.first {
		return nil, "", domain.Wrap(ErrCursorLost, "eventlog.after", "cursor is no longer retained")
	}
	if _, err := l.file.Seek(0, 0); err != nil {
		return nil, "", domain.Wrap(err, "eventlog.after", "seek log")
	}
	scanner := bufio.NewScanner(l.file)
	scanner.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	result := make([]Event, 0, limit)
	next := cursor
	for scanner.Scan() {
		var event Event
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			return nil, "", domain.Wrap(err, "eventlog.after", "decode log entry")
		}
		if event.ID <= position {
			continue
		}
		result = append(result, cloneEvent(event))
		next = Cursor(strconv.FormatUint(event.ID, 10))
		if len(result) >= limit {
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, "", domain.Wrap(err, "eventlog.after", "scan log")
	}
	return result, next, nil
}

// Latest returns the newest cursor.
func (l *FileLog) Latest(ctx context.Context) (Cursor, error) {
	if err := ctx.Err(); err != nil {
		return "", domain.Wrap(domain.ErrCanceled, "eventlog.latest", "read canceled")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.next == 0 {
		return "", nil
	}
	return Cursor(strconv.FormatUint(l.next, 10)), nil
}

// Close closes the log.
func (l *FileLog) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return nil
	}
	err := l.file.Close()
	l.file = nil
	return err
}

func parseCursor(cursor Cursor) (uint64, error) {
	if cursor == "" {
		return 0, nil
	}
	value, err := strconv.ParseUint(string(cursor), 10, 64)
	if err != nil {
		return 0, domain.Invalidf("eventlog.cursor", "invalid cursor")
	}
	return value, nil
}

func cloneEvent(event Event) Event {
	event.Payload = append([]byte(nil), event.Payload...)
	return event
}
