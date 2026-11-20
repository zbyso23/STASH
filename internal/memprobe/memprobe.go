// Package memprobe measures memory for the bounded-memory tests and the
// scale harness: retained heap after a GC, the peak of live heap objects
// while an operation runs (sampled), and the process RSS high-water mark.
package memprobe

import (
	"bufio"
	"os"
	"runtime"
	"runtime/metrics"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// Retained returns the live heap after two full collections.
func Retained() uint64 {
	runtime.GC()
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapAlloc
}

// Sampler tracks the peak of live heap objects until End.
type Sampler struct {
	stop chan struct{}
	done chan struct{}
	peak atomic.Uint64
}

// Start begins sampling every interval (200µs when zero).
func Start(interval time.Duration) *Sampler {
	if interval <= 0 {
		interval = 200 * time.Microsecond
	}
	s := &Sampler{stop: make(chan struct{}), done: make(chan struct{})}
	m := []metrics.Sample{{Name: "/memory/classes/heap/objects:bytes"}}
	go func() {
		defer close(s.done)
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			metrics.Read(m)
			if v := m[0].Value.Uint64(); v > s.peak.Load() {
				s.peak.Store(v)
			}
			select {
			case <-s.stop:
				return
			case <-t.C:
			}
		}
	}()
	return s
}

// End stops sampling and returns the peak live heap in bytes.
func (s *Sampler) End() uint64 {
	close(s.stop)
	<-s.done
	return s.peak.Load()
}

// RSS returns the current resident set and its high-water mark in bytes
// (Linux; zero elsewhere).
func RSS() (cur, peak uint64) {
	f, err := os.Open("/proc/self/status")
	if err != nil {
		return 0, 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		fs := strings.Fields(v)
		if len(fs) == 0 {
			continue
		}
		n, _ := strconv.ParseUint(fs[0], 10, 64)
		switch k {
		case "VmRSS":
			cur = n << 10
		case "VmHWM":
			peak = n << 10
		}
	}
	return cur, peak
}

// ResetPeakRSS resets the RSS high-water mark (Linux 4.0+), so a phase
// can be measured on its own. It reports whether the reset worked.
func ResetPeakRSS() bool {
	return os.WriteFile("/proc/self/clear_refs", []byte("5"), 0) == nil
}
