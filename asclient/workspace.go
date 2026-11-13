package asclient

import (
	"encoding/json"
	"errors"
	"net/http"
)

// WorkspaceHeader is the request header by which a page says which organisation
// it was opened for. A back-end that keeps one session per browser compares it
// with the session's organisation (CheckWorkspace) before serving the request,
// so a page opened while the session was in another organisation is noticed. The
// back-end always acts in the session's organisation, whatever the header says:
// the header is never a rights check and never chooses the organisation.
const WorkspaceHeader = "Workspace-Id"

// OtherWorkspaceCode is the code of the refusal CheckWorkspace returns.
const OtherWorkspaceCode = "err:session:otherWorkspace"

// NotMemberCode is the code of the Auth Service's refusal of an organisation the
// person is not in.
const NotMemberCode = "err:membership:notMember"

const otherWorkspaceDetail = "this page was opened for another workspace"

// WorkspaceRefusal is CheckWorkspace's answer for a page left open on another
// workspace. A back-end answers it as its own problem document with this
// status, code and detail. It is a check against a stale page, not a rights
// check: it names neither organisation and decides nothing about what the person
// may do.
type WorkspaceRefusal struct {
	Status int
	Code   string
	Detail string
}

// Error is the code, ": " and the detail.
func (r *WorkspaceRefusal) Error() string { return r.Code + ": " + r.Detail }

// StatusCode is the HTTP status to answer with.
func (r *WorkspaceRefusal) StatusCode() int { return r.Status }

// CheckWorkspace compares the organisation a page says it was opened for (asked,
// the WorkspaceHeader's value) with the session's (held). An empty asked is
// served: a page that says nothing is not refused. An asked equal to held,
// compared exactly as given, is served. Anything else, an empty held included, is
// refused with a *WorkspaceRefusal (status 409, code OtherWorkspaceCode) that
// names neither organisation.
func CheckWorkspace(asked, held string) error {
	if asked == "" || asked == held {
		return nil
	}

	return &WorkspaceRefusal{Status: http.StatusConflict, Code: OtherWorkspaceCode, Detail: otherWorkspaceDetail}
}

// NotMember reports whether err is, or wraps, the Auth Service's refusal of an
// organisation the person is not in: an *Error with status 403 whose body is a
// JSON object whose code is NotMemberCode. The authority answers the same refusal
// to a person with no membership at all and to a refresh whose organisation is
// gone, so it does not show that another organisation exists: a back-end may sign
// the person in again naming none, once, and must not loop.
func NotMember(err error) bool {
	var e *Error
	if !errors.As(err, &e) || e.Status != http.StatusForbidden {
		return false
	}
	var body struct {
		Code string `json:"code"`
	}
	if json.Unmarshal([]byte(e.Body), &body) != nil {
		return false
	}

	return body.Code == NotMemberCode
}
