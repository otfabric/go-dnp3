// SPDX-License-Identifier: MIT

package client

import (
	"errors"
	"reflect"
	"testing"
	"time"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/app"
)

// TestActivateConfigAnswers: the g91v1 answers of outstations other than
// go-dnp3, by the name of the requested file.
func TestActivateConfigAnswers(t *testing.T) {
	c := dialScripted(t, func(req *app.Fragment) (app.IIN, []app.Header) {
		if req.Function != app.FuncActivateConfig {
			return 0, nil
		}
		name := req.Headers[0].Objects[0].Value.(app.FileSpecification).Name
		switch name {
		case "dsc":
			// DSC go-dnp3: qualifier 0x07, no delay, one status, code 0.
			return 0, []app.Header{app.Counted(app.G91V1, app.Raw{Data: []byte{0, 0, 0, 0, 1, 1, 0}})}
		case "two":
			return 0, []app.Header{
				app.FreeFormat(app.G91V1, app.Raw{Data: []byte{0xE8, 3, 0, 0, 0}}),
				app.Counted(app.G91V1, app.Raw{Data: []byte{0, 0, 0, 0, 1, 3, 7, 'n', 'o'}}),
			}
		case "malformed":
			return 0, []app.Header{app.FreeFormat(app.G91V1, app.Raw{Data: []byte{1, 2, 3}})}
		default:
			return 0, nil
		}
	})
	spec := func(n string) app.Header { return app.FreeFormat(app.G70V8, app.FileSpecification{Name: n}) }

	got, err := c.ActivateConfig(testCtx(t), spec("dsc"))
	if err != nil || !reflect.DeepEqual(got, []app.ActivateConfigStatus{{Results: []app.ActivateConfigResult{{Code: 0}}}}) {
		t.Fatalf("dsc: %+v %v", got, err)
	}
	got, err = c.ActivateConfig(testCtx(t), spec("two"))
	want := []app.ActivateConfigStatus{{Delay: time.Second}, {Results: []app.ActivateConfigResult{{Code: 7, Text: "no"}}}}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("two: %+v %v", got, err)
	}
	for _, n := range []string{"malformed", "none"} {
		if _, err := c.ActivateConfig(testCtx(t), spec(n)); !errors.Is(err, dnp3.ErrProtocol) {
			t.Errorf("%s: %v", n, err)
		}
	}
}

func TestConfirmOptions(t *testing.T) {
	o := defaultOptions()
	if o.noSolConfirm || o.noUnsConfirm {
		t.Fatal("confirmations off by default")
	}
	for _, opt := range []Option{WithSolicitedConfirm(false), WithUnsolicitedConfirm(false)} {
		if err := opt(&o); err != nil {
			t.Fatal(err)
		}
	}
	if !o.noSolConfirm || !o.noUnsConfirm {
		t.Fatal("options not applied")
	}
	_ = WithSolicitedConfirm(true)(&o)
	_ = WithUnsolicitedConfirm(true)(&o)
	if o.noSolConfirm || o.noUnsConfirm {
		t.Fatal("options not reverted")
	}
}
