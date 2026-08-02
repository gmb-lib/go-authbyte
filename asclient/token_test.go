package asclient

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/go-quicktest/qt"
)

// jwtWith builds a token whose (unverified) payload carries the given claims, so
// the claim readers can be exercised without a real signer.
func jwtWith(claims map[string]any) string {
	payload, _ := json.Marshal(claims)
	enc := base64.RawURLEncoding.EncodeToString

	return enc([]byte(`{"alg":"none"}`)) + "." + enc(payload) + ".sig"
}

// TestParseUnverifiedReadsTheSharedClaimModel proves the readers below all decode
// into one claim model rather than each digging its own field out of the payload —
// so a claim the library already understands has exactly one definition.
func TestParseUnverifiedReadsTheSharedClaimModel(t *testing.T) {
	cl, err := ParseUnverified(jwtWith(map[string]any{
		"sub":           "u1",
		"serial_number": "PNOLV-12345",
		"login_method":  "webEid",
		"loa":           "high",
		"tenant":        "t1",
	}))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(cl.Subject, "u1"))
	qt.Check(t, qt.Equals(cl.SerialNumber, "PNOLV-12345"))
	qt.Check(t, qt.Equals(cl.LoginMethod, "webEid"))
	qt.Check(t, qt.Equals(cl.LoA, "high"))
	qt.Check(t, qt.Equals(cl.Tenant, "t1"))

	_, err = ParseUnverified("not-a-jwt")
	qt.Check(t, qt.IsNotNil(err))
}

func TestSubjectFromToken(t *testing.T) {
	qt.Check(t, qt.Equals(SubjectFromToken(jwtWith(map[string]any{"sub": "user-1"})), "user-1"))
	qt.Check(t, qt.Equals(SubjectFromToken(jwtWith(map[string]any{})), ""))
	qt.Check(t, qt.Equals(SubjectFromToken("not-a-jwt"), ""))
	qt.Check(t, qt.Equals(SubjectFromToken(""), ""))
}

func TestSerialFromToken(t *testing.T) {
	qt.Check(t, qt.Equals(SerialFromToken(jwtWith(map[string]any{"serial_number": "PNOLV-12345"})), "PNOLV-12345"))
	qt.Check(t, qt.Equals(SerialFromToken(jwtWith(map[string]any{"sub": "user-1"})), ""))
	qt.Check(t, qt.Equals(SerialFromToken("not-a-jwt"), ""))
}

func TestLoginBindingFromToken(t *testing.T) {
	// The same person via two methods → two distinct bindings, so an on-behalf
	// token cache keyed on the stable subject does not cross login methods.
	web := LoginBindingFromToken(jwtWith(map[string]any{"sub": "u1", "login_method": "webEid", "loa": "high"}))
	scan := LoginBindingFromToken(jwtWith(map[string]any{"sub": "u1", "login_method": "eidScan", "loa": "high"}))
	qt.Check(t, qt.Equals(web, "lm:webEid|loa:high"))
	qt.Check(t, qt.Equals(scan, "lm:eidScan|loa:high"))
	qt.Check(t, qt.IsTrue(web != scan))

	// No binding claims, or an unreadable token → empty (subject-only keying).
	qt.Check(t, qt.Equals(LoginBindingFromToken(jwtWith(map[string]any{"sub": "u1"})), ""))
	qt.Check(t, qt.Equals(LoginBindingFromToken("not-a-jwt"), ""))
}
