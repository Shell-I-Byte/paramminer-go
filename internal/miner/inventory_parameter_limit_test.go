package miner

import (
	"encoding/json"
	"strings"
	"testing"
)

// A single supplied request may contain arbitrarily many raw query pairs,
// even when the complete JSON document is below the 8 MiB input limit.
// Guard before net/url.ParseQuery so source validation does not depend on
// toolchain/GODEBUG-specific parser caps and cannot amplify memory without bound.
func TestInventoryQueryPairLimit(t *testing.T) {
	makeInput := func(pairCount int) []byte {
		rawURL := "https://example.invalid/test?" + strings.Repeat("a=1&", pairCount-1) + "a=1"
		data, err := json.Marshal(requestSet{Requests: []requestRecord{{Method: "GET", URL: rawURL}}})
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	for _, tc := range []struct {
		name   string
		pairs  int
		wantOK bool
	}{
		{"ordinary", 3, true},
		{"at-boundary", 10000, true},
		{"above-boundary", 10001, false},
		{"amplification", 50000, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := makeInput(tc.pairs)
			r, err := Inventory(data)
			if (err == nil) != tc.wantOK {
				t.Fatalf("pairs=%d: got err=%v", tc.pairs, err)
			}
			if tc.wantOK && (len(r.Findings) != 1 || r.Findings[0].Name != "a" || r.Findings[0].Count != 1) {
				t.Fatalf("unexpected count or finding: %+v", r.Findings)
			}
			if err != nil && strings.Contains(err.Error(), "example.invalid") {
				t.Fatal("input value leaked")
			}
		})
	}
}
