package app

// Port of guardd_client.py: the root easy-ha-proxy-guardd over its Unix
// socket. Reads the engine's state and changes its settings; the daemon
// validates every change again.

import (
	"fmt"
	"os"
	"strings"
	"time"
)

func guarddTransport() *UnixHTTP {
	return &UnixHTTP{
		Service:     "guardd",
		SocketPath:  strings.TrimSpace(envOr("GUARDD_SOCKET_PATH", "/run/easy-ha-proxy/easy-ha-proxy-guardd.sock")),
		TokenHeader: "X-Guardd-Token",
		Token:       strings.TrimSpace(os.Getenv("GUARDD_TOKEN")),
	}
}

func asObject(v any, err error) (*Map, error) {
	if err != nil {
		return nil, err
	}
	m, ok := asMap(v)
	if !ok {
		return nil, noAttr(v, "get")
	}
	return m, nil
}

func guarddGet(path string, params []QueryValue, timeout time.Duration) (*Map, error) {
	return asObject(guarddTransport().Get(path, HTTPOptions{Params: params, Timeout: timeout}))
}

// guarddChange is _change: a 400 is the operator's mistake and comes back
// as a Rejected carrying the daemon's words.
func guarddChange(path string, body any, timeout time.Duration) (*Map, error) {
	return asObject(guarddTransport().Post(path, body, HTTPOptions{Timeout: timeout, WithToken: true, RejectedStatus: 400}))
}

// guarddRequestLog is _request_log_get: a 404 with a body means the feature
// is off, not that the daemon is down.
func guarddRequestLog(path string, params []QueryValue) (*Map, error) {
	return asObject(guarddTransport().Get(path, HTTPOptions{Params: params, Timeout: 15 * time.Second, NoCheckStatus: true, RequireObject: true}))
}

func guarddBanSchedule() (*Map, error) {
	return guarddGet("/api/v1/guard/bans/schedule", nil, 2*time.Second)
}

func guarddIdentities() (*Map, error) {
	return guarddGet("/api/v1/guard/identities", nil, 2*time.Second)
}

func guarddDecisions(address string) (*Map, error) {
	return guarddGet("/api/v1/guard/decisions", []QueryValue{{"ip", address}, {"limit", "20"}}, 3*time.Second)
}

func guarddDecisionFeed(params []QueryValue) (*Map, error) {
	return guarddGet("/api/v1/guard/decisions/feed", params, 5*time.Second)
}

func guarddLive(params []QueryValue) (*Map, error) {
	return guarddRequestLog("/api/v1/guard/live", params)
}

func guarddAttackers() (*Map, error) { return guarddRequestLog("/api/v1/guard/attackers", nil) }

// guarddForgetBan tells the engine to drop its hold on an unbanned address.
func guarddForgetBan(ip string) (any, error) {
	return guarddTransport().Post("/api/v1/guard/ban/forget", newMap("ip", strings.TrimSpace(ip)),
		HTTPOptions{Timeout: 15 * time.Second, WithToken: true})
}

// guarddManualBan has the engine place an operator's ban and remember it.
func guarddManualBan(ip string) (*Map, error) {
	return asObject(guarddTransport().Post("/api/v1/guard/ban/manual", newMap("ip", strings.TrimSpace(ip)),
		HTTPOptions{Timeout: 15 * time.Second, WithToken: true, NoCheckStatus: true, RequireObject: true}))
}

func intParam(key string, n int64) QueryValue { return QueryValue{key, fmt.Sprint(n)} }
