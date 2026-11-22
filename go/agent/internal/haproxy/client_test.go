package haproxy

import (
	"bufio"
	"context"
	"net"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseShowStatAndClassify(t *testing.T) {
	csv := "# pxname,svname,scur,stot,bin,bout,hrsp_2xx,hrsp_5xx,status\n" +
		"fe_https,FRONTEND,5,100,4096,8192,98,2,OPEN\n" +
		"be_app,srv1,2,50,1024,2048,49,1,UP\n" +
		"be_app,BACKEND,2,50,1024,2048,49,1,UP\n"

	rows := ParseShowStat(csv)
	if len(rows) != 3 {
		t.Fatalf("expected 3 rows, got %d", len(rows))
	}
	key0, ok := Classify(rows[0])
	if !ok || key0.Kind != "frontend" || key0.Proxy != "fe_https" || key0.Server != "" {
		t.Fatalf("unexpected row 0 classification: %+v ok=%v", key0, ok)
	}
	key1, ok := Classify(rows[1])
	if !ok || key1.Kind != "server" || key1.Proxy != "be_app" || key1.Server != "srv1" {
		t.Fatalf("unexpected row 1 classification: %+v ok=%v", key1, ok)
	}
	key2, ok := Classify(rows[2])
	if !ok || key2.Kind != "backend" || key2.Proxy != "be_app" || key2.Server != "" {
		t.Fatalf("unexpected row 2 classification: %+v ok=%v", key2, ok)
	}
}

func TestUnixSocketShowStatAndInfo(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "admin.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				line, _ := bufio.NewReader(c).ReadString('\n')
				switch strings.TrimSpace(line) {
				case "show stat":
					_, _ = c.Write([]byte("# pxname,svname,status\nbe_site,srv1,UP\n"))
				case "show info":
					_, _ = c.Write([]byte("Name: HAProxy\nVersion: 2.8.12\nUptime_sec: 3600\n"))
				}
			}(conn)
		}
	}()

	client := NewClient(sock)
	rows, err := client.ShowStat(context.Background())
	if err != nil {
		t.Fatalf("ShowStat failed: %v", err)
	}
	if len(rows) != 1 || rows[0]["pxname"] != "be_site" || rows[0]["status"] != "UP" {
		t.Fatalf("unexpected stat rows: %+v", rows)
	}
	info, err := client.ShowInfo(context.Background())
	if err != nil {
		t.Fatalf("ShowInfo failed: %v", err)
	}
	if info["Version"] != "2.8.12" || info["Uptime_sec"] != "3600" {
		t.Fatalf("unexpected info: %+v", info)
	}
}
