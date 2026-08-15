package main

import (
	"bytes"
	"encoding/json"
	"net"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pmman289/punt/internal/tunnel"
)

func TestVersionFlag(t *testing.T) {
	previous := version
	version = "1.2.3-test"
	defer func() { version = previous }()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if err := execute([]string{"--version"}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if stdout.String() != "punt 1.2.3-test\n" {
		t.Fatalf("version output = %q", stdout.String())
	}
}

func TestStatusCommandPrintsJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "punt.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		_ = json.NewEncoder(conn).Encode(tunnel.RuntimeStatus{Mode: "server", State: "ESTABLISHED"})
	}()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if err := queryStatus([]string{"-socket", path}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), `"state": "ESTABLISHED"`) {
		t.Fatalf("status output = %q", stdout.String())
	}
}
