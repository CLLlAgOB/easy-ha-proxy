module github.com/CLLlAgOB/easy-ha-proxy/go/agent

go 1.27.4

require (
	easy-ha-proxy/panel v0.0.0
	github.com/youmark/pkcs8 v0.0.0-20240726163527-a2c0da244d78
	golang.org/x/crypto v0.59.0
	golang.org/x/net v0.63.0
	golang.org/x/sys v0.50.0
	gopkg.in/yaml.v3 v3.0.1
	modernc.org/sqlite v1.40.1
	software.sslmate.com/src/go-pkcs12 v0.5.0
)

require (
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/ncruces/go-strftime v0.1.9 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	golang.org/x/exp v0.0.0-20250620022241-b7579e27df2b // indirect
	golang.org/x/text v0.44.0 // indirect
	modernc.org/libc v1.66.10 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
)

// The Jinja engine and the Python-compatible YAML live in the panel module
// (go/panel/shared), inside the tree the panel image and its pairing label are
// built from; the agent compiles the same packages.
replace easy-ha-proxy/panel => ../panel
