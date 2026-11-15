package asclient

import (
	"net/http"
	"testing"

	"github.com/go-quicktest/qt"
)

func TestChangesIsTrueForEveryMethodThatCanChangeSomething(t *testing.T) {
	for _, m := range []string{"GET", "HEAD", "OPTIONS"} {
		qt.Check(t, qt.IsFalse(Changes(m)), qt.Commentf("method %q", m))
	}
	for _, m := range []string{"POST", "PUT", "PATCH", "DELETE", "", "get"} {
		qt.Check(t, qt.IsTrue(Changes(m)), qt.Commentf("method %q", m))
	}
}

func TestAWriteWithNoCompanyIsRefusedForAPersonInSeveralCompanies(t *testing.T) {
	err := CheckWorkspaceWrite("", "A", 2)

	var p *WorkspaceRefusal
	qt.Assert(t, qt.ErrorAs(err, &p))
	qt.Check(t, qt.Equals(p.Status, http.StatusConflict))
	qt.Check(t, qt.Equals(p.Code, "err:session:otherWorkspace"))

	var q *WorkspaceRefusal
	qt.Assert(t, qt.ErrorAs(CheckWorkspace("B", "A"), &q))
	qt.Check(t, qt.Equals(p.Detail, q.Detail))
}

func TestAWriteWithNoCompanyIsServedForAPersonInOneCompanyOrNone(t *testing.T) {
	qt.Check(t, qt.IsNil(CheckWorkspaceWrite("", "A", 1)))
	qt.Check(t, qt.IsNil(CheckWorkspaceWrite("", "A", 0)))
}

func TestAWriteNamingACompanyIsCheckedAgainstTheSessions(t *testing.T) {
	qt.Check(t, qt.IsNil(CheckWorkspaceWrite("A", "A", 2)))

	for _, n := range []int{1, 2} {
		var got, want *WorkspaceRefusal
		qt.Assert(t, qt.ErrorAs(CheckWorkspaceWrite("B", "A", n), &got))
		qt.Assert(t, qt.ErrorAs(CheckWorkspace("B", "A"), &want))
		qt.Check(t, qt.DeepEquals(got, want))
	}
}

func TestAWriteNamingACompanyAnswersAsCheckWorkspaceForAnyCount(t *testing.T) {
	asked := []string{"A", "B", "a", " A"}
	held := []string{"", "A", "B"}
	for _, a := range asked {
		for _, h := range held {
			for _, n := range []int{0, 1, 2, 3} {
				got := CheckWorkspaceWrite(a, h, n)
				want := CheckWorkspace(a, h)
				if want == nil {
					qt.Check(t, qt.IsNil(got), qt.Commentf("asked %q held %q companies %d", a, h, n))
					continue
				}
				var g, w *WorkspaceRefusal
				qt.Assert(t, qt.ErrorAs(got, &g))
				qt.Assert(t, qt.ErrorAs(want, &w))
				qt.Check(t, qt.DeepEquals(g, w), qt.Commentf("asked %q held %q companies %d", a, h, n))
			}
		}
	}
}
