package anytls

import (
	"fmt"
	"os"
	"strings"
	"time"
)

func logAnyTLSDiagf(format string, args ...any) {
	if !anyTLSDiagEnabled() {
		return
	}
	_, _ = fmt.Fprintf(
		os.Stderr,
		"[AnyTLSDiag] %s %s\n",
		time.Now().Format("15:04:05.000"),
		fmt.Sprintf(format, args...),
	)
}

func anyTLSDiagEnabled() bool {
	value := strings.TrimSpace(os.Getenv("XRAY_ANYTLS_DIAG"))
	return value == "1" || strings.EqualFold(value, "true")
}
