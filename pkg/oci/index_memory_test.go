package oci

import (
	"archive/tar"
	"fmt"
	"io"
	"runtime"
	"testing"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

// generatedLayer is a v1.Layer that synthesizes a tar stream on demand, so a
// layer with hundreds of thousands of entries never exists as one buffer.
// Only Uncompressed is implemented, which is all the filesystem indexer uses.
type generatedLayer struct {
	v1.Layer
	entries func(emit func(name string, mode int64, size int64))
}

func (l generatedLayer) Uncompressed() (io.ReadCloser, error) {
	reader, writer := io.Pipe()
	go func() {
		tw := tar.NewWriter(writer)
		var failure error
		l.entries(func(name string, mode int64, size int64) {
			if failure != nil {
				return
			}
			failure = tw.WriteHeader(&tar.Header{Name: name, Mode: mode, Size: size, Typeflag: tar.TypeReg})
			if failure == nil && size > 0 {
				_, failure = tw.Write(make([]byte, size))
			}
		})
		if failure == nil {
			failure = tw.Close()
		}
		_ = writer.CloseWithError(failure)
	}()
	return reader, nil
}

// generatedImage is a v1.Image made of generated layers. Only Layers and
// ConfigFile are implemented, which is all the filesystem indexer uses.
type generatedImage struct {
	v1.Image
	layers []v1.Layer
}

func (g generatedImage) Layers() ([]v1.Layer, error) { return g.layers, nil }
func (g generatedImage) ConfigFile() (*v1.ConfigFile, error) {
	return &v1.ConfigFile{}, nil
}

// syntheticPath returns a deterministic path with the depth and length of a
// typical package tree (about 60 bytes, five components).
func syntheticPath(i int) string {
	return fmt.Sprintf("usr/lib/python3.12/site-packages/pkg_%05d/module_%03d.py", i/200, i%200)
}

// syntheticLayer emits count regular files named by syntheticPath, offset by
// start so that several layers can contribute disjoint or overlapping names.
func syntheticLayer(start, count int) v1.Layer {
	return generatedLayer{entries: func(emit func(string, int64, int64)) {
		for i := 0; i < count; i++ {
			emit(syntheticPath(start+i), 0o644, 0)
		}
	}}
}

func syntheticImage(layers ...v1.Layer) v1.Image {
	return generatedImage{layers: layers}
}

func liveHeap() uint64 {
	runtime.GC()
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	return stats.HeapAlloc
}

// heapPeakSampler records the highest in-use heap seen while it runs. Sampling
// stops the world briefly, so the interval is coarse; the figure is a lower
// bound on the true peak, which is the safe direction for a capacity claim.
type heapPeakSampler struct {
	stop chan struct{}
	done chan uint64
}

func startHeapPeakSampler(interval time.Duration) *heapPeakSampler {
	s := &heapPeakSampler{stop: make(chan struct{}), done: make(chan uint64, 1)}
	go func() {
		var peak uint64
		var stats runtime.MemStats
		for {
			runtime.ReadMemStats(&stats)
			if stats.HeapInuse > peak {
				peak = stats.HeapInuse
			}
			select {
			case <-s.stop:
				s.done <- peak
				return
			case <-time.After(interval):
			}
		}
	}()
	return s
}

func (s *heapPeakSampler) Stop() uint64 {
	close(s.stop)
	return <-s.done
}

// indexMemory is the measured memory cost of indexing one synthetic image.
type indexMemory struct {
	entries       int
	retainedBytes uint64 // live after indexing, with the index still reachable
	peakBytes     uint64 // highest sampled in-use heap above the starting heap
}

func (m indexMemory) retainedPerEntry() float64 { return float64(m.retainedBytes) / float64(m.entries) }
func (m indexMemory) peakPerEntry() float64     { return float64(m.peakBytes) / float64(m.entries) }

// measureIndexMemory indexes a synthetic single-layer image of the given
// number of entries.
func measureIndexMemory(tb testing.TB, entries int) indexMemory {
	tb.Helper()
	before := liveHeap()
	sampler := startHeapPeakSampler(2 * time.Millisecond)
	idx, err := (&ImageReader{Image: syntheticImage(syntheticLayer(0, entries))}).streamAndIndexFilesystem(entries + 1)
	peak := sampler.Stop()
	if err != nil {
		tb.Fatalf("index %d entries: %v", entries, err)
	}
	after := liveHeap()
	runtime.KeepAlive(idx)
	if len(idx.Paths) != entries {
		tb.Fatalf("indexed %d paths, want %d", len(idx.Paths), entries)
	}
	measured := indexMemory{entries: entries}
	if after > before {
		measured.retainedBytes = after - before
	}
	if peak > before {
		measured.peakBytes = peak - before
	}
	return measured
}

// BenchmarkFilesystemIndexMemory reports the heap cost per indexed entry, the
// number the default entry cap is derived from. Run with:
//
//	go test ./pkg/oci -run '^$' -bench FilesystemIndexMemory -benchtime 1x
func BenchmarkFilesystemIndexMemory(b *testing.B) {
	for _, entries := range []int{50_000, 250_000, 1_000_000} {
		b.Run(fmt.Sprintf("entries=%d", entries), func(b *testing.B) {
			var measured indexMemory
			for i := 0; i < b.N; i++ {
				measured = measureIndexMemory(b, entries)
			}
			b.ReportMetric(measured.retainedPerEntry(), "retained-B/entry")
			b.ReportMetric(measured.peakPerEntry(), "peak-B/entry")
			b.ReportMetric(float64(measured.retainedBytes)/(1<<20), "retained-MiB")
			b.ReportMetric(float64(measured.peakBytes)/(1<<20), "peak-MiB")
		})
	}
}
