package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/Shell-I-Byte/paramminer-go/internal/miner"
)

// checkedOutput enforces io.Writer's short-write contract before a CLI run
// can claim a complete evidence object was delivered.
type checkedOutput struct {
	destination io.Writer
	err         error
}

func (c *checkedOutput) Write(p []byte) (int, error) {
	if c.err != nil {
		return 0, c.err
	}
	n, err := c.destination.Write(p)
	if err == nil && n != len(p) {
		err = io.ErrShortWrite
	}
	if err != nil {
		c.err = err
	}
	return n, err
}
func writeUsage(out io.Writer, errOut io.Writer, usage string) int {
	w := &checkedOutput{destination: out}
	if _, err := fmt.Fprintln(w, usage); err != nil || w.err != nil {
		fmt.Fprintln(errOut, "error: output failed")
		return 3
	}
	return 0
}
func run(args []string, out io.Writer, errOut io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(errOut, "usage: paramminer-go inventory --input FILE | probe --target LOOPBACK_URL --candidates FILE --authorize")
		return 2
	}
	var result miner.Result
	var err error
	switch args[0] {
	case "inventory":
		f := flag.NewFlagSet("inventory", flag.ContinueOnError)
		f.SetOutput(io.Discard)
		p := f.String("input", "", "request JSON input file, or - for stdin")
		f.Usage = func() {} // avoid leaking usage to stdout on malformed arguments
		if parseErr := f.Parse(args[1:]); errors.Is(parseErr, flag.ErrHelp) {
			return writeUsage(out, errOut, "usage: paramminer-go inventory --input FILE")
		} else if parseErr != nil || *p == "" || f.NArg() != 0 {
			fmt.Fprintln(errOut, "error: invalid inventory arguments")
			return 2
		}
		result, err = miner.ReadInventory(*p)
	case "probe":
		f := flag.NewFlagSet("probe", flag.ContinueOnError)
		f.SetOutput(io.Discard)
		target := f.String("target", "", "literal loopback URL")
		candidates := f.String("candidates", "", "candidate file")
		authorized := f.Bool("authorize", false, "confirm authorization to probe local service")
		timeout := f.Duration("timeout", 3*time.Second, "per-request timeout")
		f.Usage = func() {} // suppress usage for unknown flags
		if parseErr := f.Parse(args[1:]); errors.Is(parseErr, flag.ErrHelp) {
			return writeUsage(out, errOut, "usage: paramminer-go probe --target LOOPBACK_URL --candidates FILE --authorize [--timeout 3s]")
		} else if parseErr != nil || *target == "" || *candidates == "" || f.NArg() != 0 {
			fmt.Fprintln(errOut, "error: invalid probe arguments")
			return 2
		}
		data, e := miner.ReadCandidates(*candidates)
		if e != nil {
			err = e
			break
		}
		result, err = miner.Probe(context.Background(), miner.ProbeOptions{Target: *target, Candidates: data, Authorized: *authorized, Timeout: *timeout})
	default:
		fmt.Fprintln(errOut, "error: unknown command")
		return 2
	}
	if err != nil {
		// All miner errors are static strings; never reflect unsanitized user input.
		var p *os.PathError
		if errors.As(err, &p) {
			fmt.Fprintln(errOut, "error: file operation failed")
		} else {
			fmt.Fprintln(errOut, "error:", err)
		}
		return 3
	}
	checked := &checkedOutput{destination: out}
	enc := json.NewEncoder(checked)
	enc.SetEscapeHTML(true)
	if enc.Encode(result) != nil || checked.err != nil {
		fmt.Fprintln(errOut, "error: output failed")
		return 3
	}
	return 0
}
func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }
