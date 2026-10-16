package miner

import "testing"

// Policy permits only a literal IPv4 127/8 address or the native IPv6
// loopback ::1. IPv4-mapped IPv6 is not a native IPv6 loopback identity.
func TestLoopbackURLDoesNotCollapseIPv4MappedIPv6(t *testing.T) {
	for _, tt := range []struct {
		name, input string
		allow       bool
	}{
		{"literal IPv4 loopback", "http://127.0.0.1:8080/", true},
		{"literal IPv4 alternate loopback", "http://127.0.2.3:8080/", true},
		{"native IPv6 loopback", "http://[::1]:8080/", true},
		{"expanded native IPv6 loopback", "http://[0:0:0:0:0:0:0:1]:8080/", true},
		{"mapped IPv4 dotted", "http://[::ffff:127.0.0.1]:8080/", false},
		{"mapped IPv4 hex", "http://[::ffff:7f00:1]:8080/", false},
		{"mapped IPv4 nonloopback", "http://[::ffff:8.8.8.8]:8080/", false},
		{"nonloopback IPv4", "http://8.8.8.8:8080/", false},
		{"nonloopback IPv6", "http://[2001:db8::1]:8080/", false},
		{"zone identifier", "http://[::1%25lo]:8080/", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := validateLoopbackURL(tt.input)
			if (err == nil) != tt.allow {
				t.Fatalf("allow=%v, want=%v", err == nil, tt.allow)
			}
		})
	}
}
