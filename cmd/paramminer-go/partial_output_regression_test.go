package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// A writer that violates the io.Writer short-write contract must not cause the
// CLI to declare success after transmitting only part of its JSON evidence.
type partialNilWriter struct{}

func (partialNilWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	return len(p) - 1, nil
}

type failOutputWriter struct{}

func (failOutputWriter) Write([]byte) (int, error) { return 0, errors.New("synthetic broken pipe") }

func TestCLIRejectsPartialWriters156(t *testing.T) {
	d := t.TempDir()
	file := filepath.Join(d, "input.json")
	if err := os.WriteFile(file, []byte(`{"requests":[{"method":"GET","url":"https://example.invalid/path?alpha=1"}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"valid_inventory", []string{"inventory", "--input", file}},
		{"inventory_help", []string{"inventory", "--help"}},
		{"probe_help", []string{"probe", "--help"}},
	} {
		t.Run(tc.name+"_short_nil", func(t *testing.T) {
			var errorsOut bytes.Buffer
			code := run(tc.args, partialNilWriter{}, &errorsOut)
			if code == 0 {
				t.Fatalf("reported success with incomplete stdout; stderr=%q", errorsOut.String())
			}
		})
		t.Run(tc.name+"_hard_error", func(t *testing.T) {
			var errorsOut bytes.Buffer
			code := run(tc.args, failOutputWriter{}, &errorsOut)
			if code == 0 {
				t.Fatalf("reported success with a failing stdout writer; stderr=%q", errorsOut.String())
			}
		})
	}
}
