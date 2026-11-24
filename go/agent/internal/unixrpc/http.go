package unixrpc

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"
)

// ServeHTTP waits for active handlers before the daemon releases its state.
func ServeHTTP(ctx context.Context, srv *http.Server, ln net.Listener, grace time.Duration) error {
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ln) }()

	var err error
	select {
	case err = <-done:
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), grace)
		defer cancel()
		shutdownErr := srv.Shutdown(shutdownCtx)
		err = <-done
		if shutdownErr != nil {
			_ = srv.Close()
			return shutdownErr
		}
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
