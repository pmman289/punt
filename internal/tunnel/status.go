package tunnel

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
)

type statusServer struct {
	listener net.Listener
	path     string
}

func startStatusServer(ctx context.Context, path string, events chan<- event) (*statusServer, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, errors.New("refusing to replace a non-socket status path")
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = listener.Close()
		_ = os.Remove(path)
		return nil, err
	}
	server := &statusServer{listener: listener, path: path}
	go server.serve(ctx, events)
	return server, nil
}

func (s *statusServer) serve(ctx context.Context, events chan<- event) {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		go func() {
			defer conn.Close()
			response := make(chan RuntimeStatus, 1)
			select {
			case events <- event{type_: statusEvent, statusResponse: response}:
			case <-ctx.Done():
				return
			}
			select {
			case status := <-response:
				_ = json.NewEncoder(conn).Encode(status)
			case <-ctx.Done():
			}
		}()
	}
}

func (s *statusServer) Close() error {
	err := s.listener.Close()
	removeErr := os.Remove(s.path)
	if err != nil && !errors.Is(err, net.ErrClosed) {
		return err
	}
	if removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
		return removeErr
	}
	return nil
}
