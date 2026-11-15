package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/con-unit/con-unit/pkg/spec"
)

// Block names of attribution.json that can be carried over.
const (
	blockStudy  = "study"
	blockSeeded = "seeded"
)

// Outputs collects what an invocation computes and writes the files of the
// output directory. Every Write renders every file from the current state, so a
// snapshot after each pair leaves a consistent directory behind.
type Outputs struct {
	Dir string
	Log *Logger

	// Attribution is the document of this invocation. It is nil when the
	// invocation computes no attribution.
	Attribution *Document
	// Ablation is the ablation of this invocation, nil when it runs none.
	Ablation *AblationDocument

	// AttributionJSON and AblationJSON name the files that the LaTeX outputs
	// read for the block that this invocation does not compute. Empty means
	// attribution.json and ablation.json in Dir.
	AttributionJSON string
	AblationJSON    string

	written []string
	warned  map[string]bool
}

// loadPreviousDocument reads the attribution.json that already sits in dir. A
// file that is missing is not a problem. One that cannot be read is reported
// and ignored, and the next write replaces it.
func (o *Outputs) loadPreviousDocument() *Document {
	path := filepath.Join(o.Dir, attributionJSON)
	doc, err := LoadDocument(path)
	switch {
	case err == nil:
		return doc
	case errors.Is(err, fs.ErrNotExist):
	default:
		o.Log.Warn("ignoring the unreadable previous %s: %v", path, err)
	}
	return nil
}

// StartDocument creates the attribution document of an invocation. The study
// block describes this invocation when a study is given. Otherwise it is taken
// over from the previous attribution.json in the output directory, if that
// holds one. The seeded block is taken over the same way when this invocation
// has no truth file. Taken-over blocks are listed in carried_over.
func (o *Outputs) StartDocument(study *LoadedStudy, studyPath string, meta spec.RunMetadata, window time.Duration, minimize, hasTruth bool) *Document {
	prev := o.loadPreviousDocument()
	doc := &Document{
		SchemaVersion: documentSchemaVersion,
		Run:           meta,
		Protocol:      NewProtocol(window),
		Attributions:  []Attribution{},
	}
	doc.Protocol.Minimize = minimize
	switch {
	case study != nil:
		doc.Source = Source{StudyPath: studyPath, StudySHA256: study.SHA256, StudySchemaVersion: study.SchemaVersion}
	case prev.HasStudy():
		doc.Source, doc.Run, doc.Protocol = prev.Source, prev.Run, prev.Protocol
		doc.Summary, doc.Attributions, doc.Complete = prev.Summary, prev.Attributions, prev.Complete
		if doc.Attributions == nil {
			doc.Attributions = []Attribution{}
		}
		doc.CarriedOver = append(doc.CarriedOver, blockStudy)
		o.Log.Info("keeping the study block of the previous %s (study sha256 %s)", attributionJSON, short(prev.Source.StudySHA256))
	}
	if !hasTruth && prev != nil && prev.Seeded != nil {
		doc.Seeded = prev.Seeded
		doc.CarriedOver = append(doc.CarriedOver, blockSeeded)
		o.Log.Info("keeping the seeded block of the previous %s (%d cases)", attributionJSON, len(prev.Seeded.Cases))
	}
	return doc
}

// Write renders the output files.
func (o *Outputs) Write() error {
	o.written = o.written[:0]
	if o.Attribution != nil {
		o.Attribution.GeneratedAt = time.Now().UTC()
		if err := WriteOutputs(o.Dir, o.Attribution); err != nil {
			return err
		}
		o.written = append(o.written, attributionJSON, attributionCSV)
	}
	if o.Ablation != nil {
		if err := writeAblation(o.Dir, o.Ablation); err != nil {
			return err
		}
		o.written = append(o.written, ablationJSON)
	}

	// The LaTeX files are rendered from this invocation and from the files of
	// the other kinds of work that already sit next to it, so that every
	// invocation leaves complete macros behind.
	att, abl := o.attributionForReport(), o.ablationForReport()
	o.warnOnMixedStudies(att, abl)
	if err := writeAtomic(filepath.Join(o.Dir, macrosFile), []byte(RenderMacros(att, abl))); err != nil {
		return err
	}
	if err := writeAtomic(filepath.Join(o.Dir, tableFile), []byte(RenderTable(att, abl))); err != nil {
		return err
	}
	o.written = append(o.written, macrosFile, tableFile)
	return nil
}

// reportSource names the file to read for a block that this run lacks.
func reportSource(explicit, dir, name string) string {
	if explicit != "" {
		return explicit
	}
	return filepath.Join(dir, name)
}

// attributionForReport returns the attribution of this invocation, else the one
// on disk, else nil.
func (o *Outputs) attributionForReport() *Document {
	if o.Attribution != nil {
		return o.Attribution
	}
	path := reportSource(o.AttributionJSON, o.Dir, attributionJSON)
	doc, err := LoadDocument(path)
	switch {
	case err == nil:
		return doc
	case errors.Is(err, fs.ErrNotExist):
	default:
		o.warnOnce("ignoring the unreadable %s: %v", path, err)
	}
	return nil
}

// ablationForReport returns the ablation of this invocation, else the one on
// disk, else nil.
func (o *Outputs) ablationForReport() *AblationDocument {
	if o.Ablation != nil {
		return o.Ablation
	}
	path := reportSource(o.AblationJSON, o.Dir, ablationJSON)
	data, err := os.ReadFile(path)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			o.warnOnce("ignoring the unreadable %s: %v", path, err)
		}
		return nil
	}
	var doc AblationDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		o.warnOnce("ignoring the unreadable %s: %v", path, err)
		return nil
	}
	return &doc
}

// warnOnMixedStudies warns when the attribution and the ablation of one set of
// macros were made from different studies.
func (o *Outputs) warnOnMixedStudies(att *Document, abl *AblationDocument) {
	if !att.HasStudy() || abl == nil || abl.Source.StudySHA256 == "" {
		return
	}
	if att.Source.StudySHA256 != abl.Source.StudySHA256 {
		o.warnOnce("the attribution (study sha256 %s) and the ablation (study sha256 %s) come from different studies",
			short(att.Source.StudySHA256), short(abl.Source.StudySHA256))
	}
}

// warnOnce logs a warning the first time it is raised, because Write runs after
// every pair.
func (o *Outputs) warnOnce(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	if o.warned == nil {
		o.warned = map[string]bool{}
	}
	if o.warned[msg] {
		return
	}
	o.warned[msg] = true
	o.Log.Warn("%s", msg)
}

// writeAblation writes ablation.json atomically.
func writeAblation(dir string, doc *AblationDocument) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	doc.GeneratedAt = time.Now().UTC()
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(dir, ablationJSON), append(data, '\n'))
}

// Written lists the files of the last Write.
func (o *Outputs) Written() []string { return append([]string(nil), o.written...) }
