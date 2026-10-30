// SPDX-License-Identifier: MIT

package app

import (
	"bytes"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

// TestFileAuthenticationRedacted: printing or logging a file authentication
// object shows its user name, never its password or key.
func TestFileAuthenticationRedacted(t *testing.T) {
	v := FileAuthentication{UserName: "op", Password: "s3cret", AuthKey: 0xC0FFEE}
	var buf bytes.Buffer
	slog.New(slog.NewTextHandler(&buf, nil)).Info("auth", "object", v)
	for _, s := range []string{fmt.Sprint(v), fmt.Sprintf("%+v", v), fmt.Sprintf("%#v", v), fmt.Sprint(Object{Value: v}), buf.String()} {
		if !strings.Contains(s, "op") || strings.Contains(s, "s3cret") || strings.Contains(s, "12648430") || strings.Contains(s, "c0ffee") {
			t.Errorf("formatted: %s", s)
		}
	}
	if s := fmt.Sprint(FileAuthentication{UserName: "op"}); !strings.Contains(s, "[none]") {
		t.Errorf("without a password: %s", s)
	}
}
