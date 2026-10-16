package miner

import (
	"strings"
	"testing"
)

// Inventory evidence must not silently reinterpret malformed schema member names
// or accept a missing/null request collection as a valid empty observation.
func TestInventoryRejectsCaseFoldedJSONFields(t *testing.T) {
	cases := map[string]string{
		"alias top":       `{"Requests":[{"method":"GET","url":"https://example.invalid/?aliasTop=1"}]}`,
		"alias nested":    `{"requests":[{"Method":"GET","URL":"https://example.invalid/?aliasNested=1"}]}`,
		"root conflict":   `{"requests":[],"Requests":[{"method":"GET","url":"https://example.invalid/?overridden=1"}]}`,
		"URL conflict":    `{"requests":[{"method":"GET","url":"https://example.invalid/?first=1","URL":"https://example.invalid/?last=1"}]}`,
		"method conflict": `{"requests":[{"method":"POST","Method":"GET","url":"https://example.invalid/?x=1"}]}`,
		"escape alias":    `{"requests":[{"method":"GET","u\u0072l":"https://example.invalid/?a=1","URL":"https://example.invalid/?b=1"}]}`,
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			result, err := Inventory([]byte(data))
			if err == nil {
				t.Fatalf("accepted ambiguous input; output findings: %+v", result.Findings)
			}
			if strings.Contains(err.Error(), "example.invalid") {
				t.Fatalf("diagnostic exposed input value")
			}
		})
	}
}

func TestInventoryRejectsAbsentOrNullRequests(t *testing.T) {
	cases := map[string]string{
		"null root":     `null`,
		"empty root":    `{}`,
		"null requests": `{"requests":null}`,
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Inventory([]byte(data)); err == nil {
				t.Fatal("accepted missing/null required request list")
			}
		})
	}
	if r, err := Inventory([]byte(`{"requests":[]}`)); err != nil || len(r.Findings) != 0 {
		t.Fatalf("valid empty request array rejected: %v %+v", err, r.Findings)
	}
}
