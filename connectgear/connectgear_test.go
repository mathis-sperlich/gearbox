package connectgear_test

import (
	"context"
	"errors"
	"testing"

	"connectrpc.com/connect"

	"github.com/mathis-sperlich/gearbox"
	"github.com/mathis-sperlich/gearbox/connectgear"
)

func TestPrincipalRoundtrip(t *testing.T) {
	// Given a context carrying user-1 as the principal
	signedIn := connectgear.WithPrincipal(context.Background(), "user-1")
	// When the principal is read back from it and from an empty context
	fromSignedIn := connectgear.PrincipalFrom(signedIn)
	fromEmpty := connectgear.PrincipalFrom(context.Background())
	// Then the first is user-1 and the second is nil
	if fromSignedIn != gearbox.Principal("user-1") {
		t.Fatalf("PrincipalFrom = %v", fromSignedIn)
	}
	if fromEmpty != nil {
		t.Fatalf("empty ctx principal = %v, want nil", fromEmpty)
	}
}

func TestErr_MapsSentinelsToCodes(t *testing.T) {
	// Given each gearbox sentinel and the Connect code it maps to
	codeBySentinel := map[error]connect.Code{
		gearbox.ErrInvalidTransition: connect.CodeFailedPrecondition,
		gearbox.ErrEntityNotFound:    connect.CodeNotFound,
		gearbox.ErrUnauthorized:      connect.CodePermissionDenied,
		gearbox.ErrSaveBlocked:       connect.CodePermissionDenied,
		gearbox.ErrUnauthenticated:   connect.CodeUnauthenticated,
	}
	for sentinel, wantCode := range codeBySentinel {
		// When it is converted
		got := connect.CodeOf(connectgear.Err(sentinel))
		// Then it carries that code
		if got != wantCode {
			t.Errorf("Err(%v) code = %v, want %v", sentinel, got, wantCode)
		}
	}
}

func TestErr_NilStaysNil(t *testing.T) {
	// Given no error
	// When it is converted
	converted := connectgear.Err(nil)
	// Then there is still no error
	if converted != nil {
		t.Errorf("Err(nil) = %v, want nil", converted)
	}
}

func TestErr_UnmappedIsInternalAndWithheld(t *testing.T) {
	// Given an error whose text must not reach a client
	leakyErr := errors.New("select * from secrets failed")
	// When it is converted
	converted := connectgear.Err(leakyErr)
	// Then it is internal with a generic message
	if connect.CodeOf(converted) != connect.CodeInternal {
		t.Fatalf("code = %v, want internal", connect.CodeOf(converted))
	}
	if got := converted.Error(); got != "internal: internal error" {
		t.Fatalf("message leaked: %q", got)
	}
}
