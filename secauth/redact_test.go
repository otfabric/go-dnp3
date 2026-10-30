// SPDX-License-Identifier: MIT

package secauth

import (
	"bytes"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

// TestUserRedacted: printing or logging a user shows its number and key
// lengths, never its keys.
func TestUserRedacted(t *testing.T) {
	u := User{Number: 3, UpdateKey: bytes.Repeat([]byte{0xAB}, 16), Key: bytes.Repeat([]byte{0xCD}, 16)}
	var buf bytes.Buffer
	slog.New(slog.NewTextHandler(&buf, nil)).Info("user", "user", u)
	for _, s := range []string{fmt.Sprint(u), fmt.Sprintf("%+v", u), fmt.Sprintf("%#v", u), fmt.Sprint(&u), buf.String()} {
		if !strings.Contains(s, "16 octets") || strings.Contains(s, "171") || strings.Contains(s, "abab") || strings.Contains(s, "205") {
			t.Errorf("formatted: %s", s)
		}
	}
	if s := fmt.Sprint(User{Number: 1}); !strings.Contains(s, "[none]") {
		t.Errorf("without keys: %s", s)
	}
}
