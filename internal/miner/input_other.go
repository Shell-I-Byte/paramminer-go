//go:build !linux && !darwin && !freebsd && !netbsd && !openbsd && !dragonfly

package miner

import "os"

// Other platforms perform before/after regular-file validation. Races during
// open require further native testing and are an explicitly documented gap.
func openInputNoBlock(path string) (*os.File, error) { return os.Open(path) }
