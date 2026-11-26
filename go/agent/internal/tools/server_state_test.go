package tools

import (
	"reflect"
	"strings"
	"testing"
)

// Config-authoritative restoration of every HAProxy state field we consume.

var (
	stateHeader = "# " + strings.Join(append(append([]string(nil), serverStateFields...), serverStateOptional...), " ")
	stateRow    = "36 target 1 main 127.0.0.1 0 73 17 100 10 15 2 0 6 0 0 0 old.example.test 1025 - 0 9999 127.0.0.8 127.0.0.9 9998"
)

type restoreCase struct {
	endpoint, options, row, preamble string
}

func restoreRow(t *testing.T, c restoreCase) map[string]string {
	t.Helper()
	if c.endpoint == "" {
		c.endpoint = "new.example.test:1026"
	}
	if c.row == "" {
		c.row = stateRow
	}
	text := "1\n" + stateHeader + "\n" + c.row + "\n"
	config := c.preamble + "\nbackend target\n server main " + c.endpoint + " " + c.options + "\n"
	out, err := NormalizeServerState(text, config, true)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(out, "\n")
	values := strings.Fields(lines[2])
	if len(values) != len(serverStateFields) {
		t.Fatalf("row %q", lines[2])
	}
	row := map[string]string{}
	for i, name := range serverStateFields {
		row[name] = values[i]
	}
	return row
}

func TestANewDNSNameDoesNotReuseThePreviousAddress(t *testing.T) {
	row := restoreRow(t, restoreCase{options: "check"})
	if row["srv_addr"] != "-" || row["srv_fqdn"] != "new.example.test" || row["srv_port"] != "1026" {
		t.Fatalf("row %v", row)
	}
	if row["srv_admin_state"] != "9" || row["srv_uweight"] != "17" || row["srv_iweight"] != "100" {
		t.Fatalf("row %v", row)
	}
}

func TestTheSameDNSNameKeepsItsLastKnownAddress(t *testing.T) {
	if row := restoreRow(t, restoreCase{endpoint: "old.example.test:1026", options: "check"}); row["srv_addr"] != "127.0.0.1" {
		t.Fatalf("row %v", row)
	}
}

func TestIPToDNSClearsTheCachedAddress(t *testing.T) {
	row := restoreRow(t, restoreCase{options: "check", row: strings.Replace(stateRow, "old.example.test", "-", 1)})
	if row["srv_addr"] != "-" {
		t.Fatalf("row %v", row)
	}
}

func TestFixedAddressesAlwaysComeFromTheConfiguration(t *testing.T) {
	for endpoint, address := range map[string]string{"127.0.0.2:1043": "127.0.0.2", "[::1]:1043": "::1", "ipv4@127.0.0.3:1043": "127.0.0.3"} {
		row := restoreRow(t, restoreCase{endpoint: endpoint, options: "check"})
		if row["srv_addr"] != address || row["srv_fqdn"] != "-" || row["srv_port"] != "1043" {
			t.Fatalf("%s: %v", endpoint, row)
		}
	}
}

func TestAnUnbracketedIPv6WithoutAPortIsNotReadAsPortOne(t *testing.T) {
	host, _, hasPort, err := parseEndpoint("::1")
	if err != nil || host != "::1" || hasPort {
		t.Fatalf("%q %v %v", host, hasPort, err)
	}
}

func TestAnOldFailureCannotPinAServerAfterItsChecksAreRemoved(t *testing.T) {
	row := restoreRow(t, restoreCase{endpoint: "new.example.test:1026"})
	if row["srv_op_state"] != "2" || row["srv_check_state"] != "0" || row["srv_agent_state"] != "0" || row["srv_admin_state"] != "9" {
		t.Fatalf("row %v", row)
	}
}

func TestHealthFailureAndExplicitDisableAreKeptWhileChecksExist(t *testing.T) {
	row := restoreRow(t, restoreCase{options: "check", row: strings.Replace(stateRow, " 6 0 0 0 ", " 2 0 0 0 ", 1)})
	if row["srv_op_state"] != "0" || row["srv_check_state"] != "2" {
		t.Fatalf("row %v", row)
	}
}

func TestAnAgentCheckAloneStillPreservesHealthState(t *testing.T) {
	if row := restoreRow(t, restoreCase{options: "agent-check agent-port 9876"}); row["srv_op_state"] != "0" {
		t.Fatalf("row %v", row)
	}
}

func TestDefaultChecksAndServerOverridesAreRespected(t *testing.T) {
	preamble := "defaults\n default-server check agent-check\n"
	if row := restoreRow(t, restoreCase{preamble: preamble}); row["srv_op_state"] != "0" {
		t.Fatalf("defaults: %v", row)
	}
	if row := restoreRow(t, restoreCase{options: "no-check no-agent-check", preamble: preamble}); row["srv_op_state"] != "2" {
		t.Fatalf("overrides: %v", row)
	}
}

func TestTheSameSRVRecordKeepsDiscoveryButAChangedOneDropsTheOldTarget(t *testing.T) {
	row := strings.Replace(stateRow, "old.example.test 1025 -", "target.example.test 1025 _old._tcp.example.test", 1)
	same := restoreRow(t, restoreCase{endpoint: "_old._tcp.example.test", options: "check", row: row})
	if same["srv_addr"] != "127.0.0.1" || same["srv_port"] != "1025" || same["srvrecord"] != "_old._tcp.example.test" {
		t.Fatalf("same %v", same)
	}
	changed := restoreRow(t, restoreCase{endpoint: "_new._tcp.example.test", options: "check", row: row})
	if changed["srv_addr"] != "-" || changed["srv_fqdn"] != "-" || changed["srv_port"] != "0" || changed["srvrecord"] != "-" {
		t.Fatalf("changed %v", changed)
	}
}

func TestEveryOptionalTransportOverrideIsRemoved(t *testing.T) {
	out, err := NormalizeServerState("1\n"+stateHeader+"\n"+stateRow+"\n", "\nbackend target\n server main new.example.test:1026 check\n", true)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(out, "\n")
	if lines[1] != "# "+strings.Join(serverStateFields, " ") || len(strings.Fields(lines[2])) != len(serverStateFields) {
		t.Fatalf("header %q row %q", lines[1], lines[2])
	}
	for _, optional := range serverStateOptional {
		if strings.Contains(lines[1], optional) {
			t.Fatalf("%s kept", optional)
		}
	}
}

func TestAnUnknownHeaderATruncatedRowAndANonNumericStateAreRejected(t *testing.T) {
	fields := strings.Fields(stateRow)
	for _, text := range []string{
		"2\n" + stateHeader + "\n" + stateRow,
		"1\n# be_id broken\n" + stateRow,
		"1\n" + stateHeader + "\n" + strings.Join(fields[:len(fields)-1], " "),
		"1\n" + stateHeader + "\n" + strings.Replace(stateRow, " 73 ", " invalid ", 1),
	} {
		if _, err := NormalizeServerState(text, "", true); err == nil {
			t.Fatalf("accepted %q", text)
		}
	}
}

func TestAnEmptyInitialStateIsSupported(t *testing.T) {
	out, err := NormalizeServerState("1\n", "", false)
	if err != nil || !reflect.DeepEqual(out, "1\n") {
		t.Fatalf("%q %v", out, err)
	}
}
