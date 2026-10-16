//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package miner

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestRegularFileBoundaryNoFIFOHang(t *testing.T) {
	d := t.TempDir()
	fifo := filepath.Join(d, "in.fifo")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Skipf("no FIFO support: %v", err)
	}
	fifoLink := filepath.Join(d, "fifo-link")
	if err := os.Symlink(fifo, fifoLink); err != nil {
		t.Fatal(err)
	}
	regular := filepath.Join(d, "in.json")
	valid := []byte(`{"requests":[]}`)
	if err := os.WriteFile(regular, valid, 0600); err != nil {
		t.Fatal(err)
	}
	regLink := filepath.Join(d, "regular-link")
	if err := os.Symlink(regular, regLink); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{fifo, fifoLink, d} {
		t.Run(filepath.Base(path), func(t *testing.T) {
			if _, err := readFile(path, maxInput); err == nil {
				t.Fatal("accepted nonregular inventory file")
			}
			if _, err := readFile(path, 64<<10); err == nil {
				t.Fatal("accepted nonregular candidate file")
			}
		})
	}
	for _, path := range []string{regular, regLink} {
		got, err := readFile(path, maxInput)
		if err != nil || string(got) != string(valid) {
			t.Fatalf("regular input failed: %v %q", err, got)
		}
	}
	if _, err := readFile(filepath.Join(d, "missing"), maxInput); err == nil {
		t.Fatal("accepted missing file")
	}
}
