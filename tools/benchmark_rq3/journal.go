package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// Journal is an append-only JSON Lines file with one line per trial. Each
// line is flushed to stable storage before Record returns, so a crash or kill
// loses at most the trial in flight. The format follows docs/CONTRACT.md
// section 5.
type Journal struct {
	mu   sync.Mutex
	f    *os.File
	path string
}

// OpenJournal creates the journal. An existing file at the path is moved to
// <path>.<mtime> first, so a new run never mixes with the lines of an earlier
// run and no earlier line is lost.
func OpenJournal(path string) (*Journal, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	if st, err := os.Stat(path); err == nil {
		rotated := fmt.Sprintf("%s.%s", path, st.ModTime().UTC().Format("20060102T150405Z"))
		if err := os.Rename(path, rotated); err != nil {
			return nil, fmt.Errorf("rotating existing journal: %w", err)
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	return &Journal{f: f, path: path}, nil
}

// Path returns the journal file path.
func (j *Journal) Path() string { return j.path }

// Record appends one trial and syncs the file.
func (j *Journal) Record(t TrialRecord) error {
	line, err := json.Marshal(t)
	if err != nil {
		return err
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if _, err := j.f.Write(append(line, '\n')); err != nil {
		return err
	}
	return j.f.Sync()
}

// Close closes the file.
func (j *Journal) Close() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.f.Close()
}

// ReadJournal returns the trials of a journal file in order. A truncated last
// line, as left by a crash, is ignored.
func ReadJournal(path string) ([]TrialRecord, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []TrialRecord
	start := 0
	for i := 0; i <= len(data); i++ {
		if i < len(data) && data[i] != '\n' {
			continue
		}
		line := data[start:i]
		start = i + 1
		if len(line) == 0 {
			continue
		}
		var t TrialRecord
		if err := json.Unmarshal(line, &t); err != nil {
			if i == len(data) {
				break
			}
			return nil, fmt.Errorf("journal line is not valid JSON: %w", err)
		}
		out = append(out, t)
	}
	return out, nil
}
