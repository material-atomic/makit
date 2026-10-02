package shield

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Snapshot is one request as makit saw it. No bodies, no cookies, no authorization headers.
type Snapshot struct {
	Time     time.Time `json:"time"`
	Listener string    `json:"listener"`
	Decision
	Method  string `json:"method,omitempty"`
	Host    string `json:"host,omitempty"`
	URI     string `json:"uri,omitempty"`
	UA      string `json:"ua,omitempty"`
	Referer string `json:"referer,omitempty"`
	Country string `json:"country,omitempty"`
	Ray     string `json:"cf_ray,omitempty"`
	Status  int    `json:"status,omitempty"`
	Ms      int64  `json:"ms,omitempty"`
}

// Recorder appends snapshots as JSON lines and rotates by size.
type Recorder struct {
	mu   sync.Mutex
	path string
	max  int64
	keep int
	f    *os.File
	size int64
}

func NewRecorder(path string, maxMB, keep int) (*Recorder, error) {
	if path == "" {
		return nil, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}
	r := &Recorder{path: path, max: int64(maxMB) << 20, keep: keep}
	return r, r.open()
}

func (r *Recorder) open() error {
	f, err := os.OpenFile(r.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	st, _ := f.Stat()
	r.f, r.size = f, st.Size()
	return nil
}

func (r *Recorder) Write(s Snapshot) {
	if r == nil {
		return
	}
	b, _ := json.Marshal(s)
	b = append(b, '\n')
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.max > 0 && r.size+int64(len(b)) > r.max {
		r.rotate()
	}
	n, _ := r.f.Write(b)
	r.size += int64(n)
}

func (r *Recorder) rotate() {
	r.f.Close()
	for i := r.keep - 1; i >= 1; i-- {
		_ = os.Rename(fmt.Sprintf("%s.%d", r.path, i), fmt.Sprintf("%s.%d", r.path, i+1))
	}
	_ = os.Rename(r.path, r.path+".1")
	_ = os.Remove(fmt.Sprintf("%s.%d", r.path, r.keep+1))
	_ = r.open()
}
