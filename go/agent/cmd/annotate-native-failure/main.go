// Command annotate-native-failure exposes disposable native-test failures
// through GitHub check annotations (the HAProxy 3.4 qualification jobs).
package main

import (
	"fmt"
	"os"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		return
	}
	raw, err := os.ReadFile(os.Args[1])
	if err != nil {
		return
	}
	tail := []rune(string(raw))
	if len(tail) > 5000 {
		tail = tail[len(tail)-5000:]
	}
	text := strings.ReplaceAll(string(tail), "%", "%25")
	text = strings.ReplaceAll(text, "\r", "%0D")
	text = strings.ReplaceAll(text, "\n", "%0A")
	fmt.Println("::error title=Native HAProxy qualification::" + text)
}
