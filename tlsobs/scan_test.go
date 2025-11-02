package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestScanTooManyRequests(t *testing.T) {
	t.Parallel()
	server := testServer(http.StatusTooManyRequests, "try later")
	defer server.Close()
	_, err := postScan(mustURL(server.URL))
	if err.Error() != fmt.Sprintf("scan failed with error code 429: try later") {
		t.Fatalf("server responded with too many requests and client did not handle it")
	}
}

func TestScanOK(t *testing.T) {
	t.Parallel()
	server := testServer(http.StatusOK, "{\"scan_id\": 3}")
	defer server.Close()
	scanID, err := postScan(mustURL(server.URL))
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if scanID != 3 {
		t.Fatalf("unexpected scan id: %d [expected 3]", scanID)
	}
}

func testServer(statusCode int, body string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(statusCode)
		_, _ = w.Write([]byte(body))
	}))
}
