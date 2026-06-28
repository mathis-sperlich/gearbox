package connectgear_test

import (
	"context"
	"errors"
	"testing"

	"connectrpc.com/connect"

	"github.com/mathis-sperlich/gearbox"
	"github.com/mathis-sperlich/gearbox/connectgear"
)

func TestErr_MapsSentinelsToCodes(t *testing.T) {
	cases := map[error]connect.Code{
		gearbox.ErrInvalidTransition: connect.CodeFailedPrecondition,
		gearbox.ErrEntityNotFound:    connect.CodeNotFound,
		gearbox.ErrUnauthorized:      connect.CodePermissionDenied,
		gearbox.ErrSaveBlocked:       connect.CodePermissionDenied,
		gearbox.ErrUnauthenticated:   connect.CodeUnauthenticated,
	}
	for in, want := range cases {
		if got := connect.CodeOf(connectgear.Err(in)); got != want {
			t.Errorf("Err(%v) code = %v, want %v", in, got, want)
		}
	}
	if connectgear.Err(nil) != nil {
		t.Error("Err(nil) should be nil")
	}
}

func TestErr_UnmappedIsInternalAndWithheld(t *testing.T) {
	e := connectgear.Err(errors.New("select * from secrets failed"))
	if connect.CodeOf(e) != connect.CodeInternal {
		t.Fatalf("code = %v, want internal", connect.CodeOf(e))
	}
	if got := e.Error(); got != "internal: internal error" {
		t.Fatalf("message leaked: %q", got)
	}
}

func TestPrincipalRoundtrip(t *testing.T) {
	ctx := connectgear.WithPrincipal(context.Background(), "user-1")
	if p := connectgear.PrincipalFrom(ctx); p != gearbox.Principal("user-1") {
		t.Fatalf("PrincipalFrom = %v", p)
	}
	if p := connectgear.PrincipalFrom(context.Background()); p != nil {
		t.Fatalf("empty ctx principal = %v, want nil", p)
	}
}
