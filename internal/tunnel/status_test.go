package tunnel

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestStatusSocketReturnsRuntimeStatus(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "punt.sock")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events := make(chan event, 1)
	server, err := startStatusServer(ctx, path, events)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("status socket permissions = %o, want 600", info.Mode().Perm())
	}

	want := RuntimeStatus{Mode: "client", Transport: "tcp", State: "ESTABLISHED", Network: "192.0.2.2:42487", Listen: "127.0.0.1:8080", ActiveFlows: 2, Stats: RuntimeStats{RawIn: 9}}
	go func() {
		ev := <-events
		ev.statusResponse <- want
	}()
	conn, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var got RuntimeStatus
	if err := json.NewDecoder(conn).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Mode != want.Mode || got.Transport != want.Transport || got.State != want.State || got.Listen != want.Listen || got.ActiveFlows != want.ActiveFlows || got.Stats.RawIn != want.Stats.RawIn {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}
