// Package journal implements the append-only JSON Lines journal described in
// docs/CONTRACT.md section 5. Each line is one spec.SuiteResult, appended and
// flushed to stable storage after the image finishes, so a crash never loses
// a completed image. The last record per requested_ref wins.
package journal

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/con-unit/con-unit/pkg/spec"
)

// Writer appends records to a journal file.
type Writer struct {
	mu   sync.Mutex
	file *os.File
	path string
}

// Open opens the journal for appending, creating it and its directory. A torn
// final line left by a crash is repaired first so new records never join it.
func Open(path string) (*Writer, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create journal directory: %w", err)
	}
	if err := repairTail(path); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open journal %s: %w", path, err)
	}
	return &Writer{file: file, path: path}, nil
}

// repairTail makes sure the journal ends with a newline. A final line without
// one is kept when it is a complete record and truncated when it is not.
func repairTail(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("read journal %s: %w", path, err)
	}
	if len(data) == 0 || data[len(data)-1] == '\n' {
		return nil
	}
	lastNewline := bytes.LastIndexByte(data, '\n')
	tail := data[lastNewline+1:]
	var record spec.SuiteResult
	if json.Unmarshal(bytes.TrimSpace(tail), &record) == nil {
		file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			return fmt.Errorf("repair journal %s: %w", path, err)
		}
		defer file.Close()
		if _, err := file.Write([]byte{'\n'}); err != nil {
			return fmt.Errorf("repair journal %s: %w", path, err)
		}
		return file.Sync()
	}
	if err := os.Truncate(path, int64(lastNewline+1)); err != nil {
		return fmt.Errorf("truncate torn journal line in %s: %w", path, err)
	}
	return nil
}

// Path returns the journal file path.
func (w *Writer) Path() string { return w.path }

// Append writes one record as a single JSON line and flushes it to disk.
func (w *Writer) Append(record *spec.SuiteResult) error {
	if record == nil {
		return errors.New("journal: nil record")
	}
	line, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("journal: encode record for %s: %w", record.RequestedRef, err)
	}
	line = append(line, '\n')
	w.mu.Lock()
	defer w.mu.Unlock()
	if _, err := w.file.Write(line); err != nil {
		return fmt.Errorf("journal: write %s: %w", w.path, err)
	}
	if err := w.file.Sync(); err != nil {
		return fmt.Errorf("journal: sync %s: %w", w.path, err)
	}
	return nil
}

// Close closes the journal file.
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.file.Close()
}

// Read loads all records of a journal. A missing file yields no records. A
// malformed final line is the signature of a crash during an append and is
// skipped, which is reported in the second result. A malformed line anywhere
// else is an error, because it means the journal was edited or corrupted.
func Read(path string) (records []*spec.SuiteResult, skippedTrailing bool, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("read journal %s: %w", path, err)
	}
	return Decode(bytes.NewReader(data))
}

// Decode parses journal lines from r with the semantics of Read.
func Decode(r io.Reader) (records []*spec.SuiteResult, skippedTrailing bool, err error) {
	reader := bufio.NewReaderSize(r, 1<<20)
	lineNumber := 0
	for {
		line, readErr := reader.ReadBytes('\n')
		atEOF := errors.Is(readErr, io.EOF)
		if readErr != nil && !atEOF {
			return nil, false, fmt.Errorf("read journal: %w", readErr)
		}
		trimmed := bytes.TrimSpace(line)
		if len(trimmed) > 0 {
			lineNumber++
			var record spec.SuiteResult
			if decodeErr := json.Unmarshal(trimmed, &record); decodeErr != nil {
				if atEOF {
					return records, true, nil
				}
				return nil, false, fmt.Errorf("journal line %d is not a valid record: %w", lineNumber, decodeErr)
			}
			records = append(records, &record)
		}
		if atEOF {
			return records, false, nil
		}
	}
}

// Latest reduces records to the last one per requested_ref (falling back to
// image_name for records written without a requested_ref).
func Latest(records []*spec.SuiteResult) map[string]*spec.SuiteResult {
	latest := make(map[string]*spec.SuiteResult, len(records))
	for _, record := range records {
		latest[Key(record)] = record
	}
	return latest
}

// Key is the identity of a record inside the journal.
func Key(record *spec.SuiteResult) string {
	if record.RequestedRef != "" {
		return record.RequestedRef
	}
	return record.ImageName
}

// Completed reports whether the record is a COMPLETED image record. An empty
// status is treated as COMPLETED for records written by older versions.
func Completed(record *spec.SuiteResult) bool {
	return record != nil && (record.Status == spec.StatusCompleted || record.Status == "")
}

// RotateIfPresent moves a non-empty journal aside so a fresh run never mixes
// its records with an earlier run. It returns the new path, or an empty
// string when nothing was moved.
func RotateIfPresent(path string, now time.Time) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		return "", fmt.Errorf("stat journal %s: %w", path, err)
	}
	if info.Size() == 0 {
		return "", nil
	}
	rotated := fmt.Sprintf("%s.%s.bak", path, now.UTC().Format("20060102T150405Z"))
	if err := os.Rename(path, rotated); err != nil {
		return "", fmt.Errorf("rotate journal %s: %w", path, err)
	}
	return rotated, nil
}
