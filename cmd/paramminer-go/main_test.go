package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLIInventoryAndNoSecretOutput(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "input.json")
	if err := os.WriteFile(p, []byte(`{"requests":[{"method":"GET","url":"https://example.invalid/private?token=sensitive"}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	var out, errs bytes.Buffer
	ret := run([]string{"inventory", "--input", p}, &out, &errs)
	if ret != 0 || !strings.Contains(out.String(), `"name":"token"`) || strings.Contains(out.String(), "sensitive") || errs.Len() != 0 {
		t.Fatalf("exit=%d out=%s err=%s", ret, out.String(), errs.String())
	}
}
func TestCLIFlagInjectionAndExitCodes(t *testing.T) {
	for _, args := range [][]string{{}, {"bad"}, {"inventory", "--evil\nFORGED=YES"}, {"probe", "--target", "http://8.8.8.8/", "--candidates", "x"}, {"inventory", "--input", "/nonexistent"}} {
		var out, stderr bytes.Buffer
		code := run(args, &out, &stderr)
		if code == 0 {
			t.Fatalf("unexpected success: %v", args)
		}
		if strings.Contains(stderr.String(), "FORGED=YES") || strings.Contains(stderr.String(), "/nonexistent") || out.Len() != 0 {
			t.Fatalf("injected output: %s %s", out.String(), stderr.String())
		}
	}
}

func TestHelpIsSuccessfulAndUnknownFlagsStillRejected(t *testing.T) {
	for _, cmd := range []string{"inventory", "probe"} {
		for _, h := range []string{"-h", "-help", "--help"} {
			var stdout, stderr bytes.Buffer
			code := run([]string{cmd, h}, &stdout, &stderr)
			if code != 0 || stderr.Len() != 0 || !strings.Contains(stdout.String(), "usage: paramminer-go "+cmd) {
				t.Fatalf("%s %s: code=%d stdout=%q stderr=%q", cmd, h, code, stdout.String(), stderr.String())
			}
		}
		var stdout, stderr bytes.Buffer
		if code := run([]string{cmd, "--unknown"}, &stdout, &stderr); code != 2 || stdout.Len() != 0 {
			t.Fatalf("invalid flag accepted for %s: code=%d out=%q", cmd, code, stdout.String())
		}
	}
}
