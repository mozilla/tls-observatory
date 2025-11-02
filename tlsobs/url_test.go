package main

import (
	"fmt"
	"testing"
)

func TestBuildScanURL(t *testing.T) {
	t.Parallel()
	//goland:noinspection HttpUrlsUsage
	testCases := []struct {
		targetURL   string
		rescan      bool
		expectedURL string
	}{
		{"target.com", false, "https://observatory.com/api/v1/scan?target=target.com"},
		{"http://target.com", false, "https://observatory.com/api/v1/scan?target=target.com"},
		{"https://target.com", false, "https://observatory.com/api/v1/scan?target=target.com"},
		{"https://target.com", true, "https://observatory.com/api/v1/scan?target=target.com&rescan=true"},
		{"https://target.com/", true, "https://observatory.com/api/v1/scan?target=target.com&rescan=true"},
	}

	for _, tc := range testCases {
		name := fmt.Sprintf("target=%s rescan=%t", tc.targetURL, tc.rescan)
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			u := buildScanURL("https://observatory.com", tc.targetURL, tc.rescan)
			if u != tc.expectedURL {
				t.Fatalf("expected '%s' == '%s'", u, tc.expectedURL)
			}
		})
	}
}

func TestMustURL(t *testing.T) {
	t.Parallel()
	testCases := []string{
		"https://observatory.com",
		"observatory.com",
		"foo",
	}
	for _, tc := range testCases {
		t.Run(tc, func(t *testing.T) {
			t.Parallel()
			u := mustURL(tc)
			if u.String() != tc {
				t.Fatalf("expected '%s'", tc)
			}
		})
	}
}
