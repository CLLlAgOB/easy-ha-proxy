package unixrpc

import (
	"context"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestServeHTTPDrainsActiveRequest(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started, release, shuttingDown := make(chan struct{}), make(chan struct{}), make(chan struct{})
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(started)
		<-release
		_, _ = io.WriteString(w, "finished")
	})}
	srv.RegisterOnShutdown(func() { close(shuttingDown) })
	done := make(chan error, 1)
	go func() { done <- ServeHTTP(ctx, srv, ln, 3*time.Second) }()

	response := make(chan string, 1)
	go func() {
		client := &http.Client{Timeout: 4 * time.Second}
		resp, err := client.Get("http://" + ln.Addr().String())
		if err != nil {
			response <- err.Error()
			return
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			response <- err.Error()
			return
		}
		response <- string(body)
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		close(release)
		t.Fatal("request did not reach the handler")
	}
	cancel()
	select {
	case <-shuttingDown:
	case <-time.After(time.Second):
		close(release)
		t.Fatal("listener did not begin shutdown")
	}
	select {
	case err := <-done:
		close(release)
		t.Fatalf("server exited before the request finished: %v", err)
	default:
		close(release)
	}
	if got := <-response; got != "finished" {
		t.Fatalf("handler did not finish: %q", got)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
