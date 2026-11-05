package asclient

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// The AI apps connected as assistants, read and signed out at the Auth Service's
// identity door with the signed-in person's own token: a person's own, or, for
// a workspace's administrator, any one assistant's. Each connection is named by
// its public name, never a session's key or a token.

// Connection is one AI app connected as an assistant: its public name, the app's
// own name, when it connected and when a call last went through it (nil until
// one did).
type Connection struct {
	ID          string     `json:"id"`
	App         string     `json:"app"`
	ConnectedAt time.Time  `json:"connectedAt"`
	LastUsed    *time.Time `json:"lastUsed"`
}

// OwnAssistant is one of the signed-in person's own assistants in the workspace
// their token names, with the apps connected as it, newest first.
type OwnAssistant struct {
	Key         string       `json:"key"`
	Name        string       `json:"name"`
	Connections []Connection `json:"connections"`
}

// errNothingNamed is a call that names no token, connection or assistant, or one
// that would leave its path segment; it is refused before anything is sent.
var errNothingNamed = errors.New("asclient: a connections call names no token, or no connection or assistant it can address")

// OwnConnections reads the person's own assistants in the workspace their token
// names, each with the apps connected as it.
func (c *Client) OwnConnections(ctx context.Context, key *ecdsa.PrivateKey, accessToken string) ([]OwnAssistant, error) {
	var out struct {
		Assistants []OwnAssistant `json:"assistants"`
	}
	if err := c.connectionsRead(ctx, key, accessToken, "/identity/connections", &out); err != nil {
		return nil, err
	}

	return out.Assistants, nil
}

// SignOutOwnConnection signs out one of the person's own connected apps by its
// public name: it stops at once, the person's others go on.
func (c *Client) SignOutOwnConnection(ctx context.Context, key *ecdsa.PrivateKey, accessToken, id string) error {
	seg, ok := segment(id)
	if !ok {
		return errNothingNamed
	}

	return c.connectionsEnd(ctx, key, accessToken, "/identity/connections/"+seg)
}

// AssistantConnections reads, for an administrator of the workspace the token
// names, the apps connected as one of its assistants.
func (c *Client) AssistantConnections(ctx context.Context, key *ecdsa.PrivateKey, accessToken, assistant string) ([]Connection, error) {
	seg, ok := segment(assistant)
	if !ok {
		return nil, errNothingNamed
	}
	var out struct {
		Connections []Connection `json:"connections"`
	}
	if err := c.connectionsRead(ctx, key, accessToken, "/identity/assistants/"+seg+"/connections", &out); err != nil {
		return nil, err
	}

	return out.Connections, nil
}

// SignOutAssistantConnection signs out, for an administrator of the workspace,
// one app connected as one of its assistants.
func (c *Client) SignOutAssistantConnection(ctx context.Context, key *ecdsa.PrivateKey, accessToken, assistant, id string) error {
	a, ok := segment(assistant)
	if !ok {
		return errNothingNamed
	}
	seg, ok := segment(id)
	if !ok {
		return errNothingNamed
	}

	return c.connectionsEnd(ctx, key, accessToken, "/identity/assistants/"+a+"/connections/"+seg)
}

// EndAssistantConnections signs out, for an administrator of the workspace,
// every app connected as one of its assistants, as its removal asks first.
func (c *Client) EndAssistantConnections(ctx context.Context, key *ecdsa.PrivateKey, accessToken, assistant string) error {
	seg, ok := segment(assistant)
	if !ok {
		return errNothingNamed
	}

	return c.connectionsEnd(ctx, key, accessToken, "/identity/assistants/"+seg+"/connections")
}

// segment answers a name as one path segment, or false for an empty name or one
// a path would read as more than a segment.
func segment(name string) (string, bool) {
	if strings.TrimSpace(name) == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\\?#%") {
		return "", false
	}

	return url.PathEscape(name), true
}

// connectionsRead GETs path with the person's token and decodes a 200 answer.
func (c *Client) connectionsRead(ctx context.Context, key *ecdsa.PrivateKey, accessToken, path string, out any) error {
	if strings.TrimSpace(accessToken) == "" {
		return errNothingNamed
	}
	body, status, err := c.dpopDo(ctx, key, http.MethodGet, path, accessToken, "", nil)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return &Error{Status: status, Body: string(body)}
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("asclient: decode connections response: %w", err)
	}

	return nil
}

// connectionsEnd DELETEs path with the person's token; only a 204 is done.
func (c *Client) connectionsEnd(ctx context.Context, key *ecdsa.PrivateKey, accessToken, path string) error {
	if strings.TrimSpace(accessToken) == "" {
		return errNothingNamed
	}
	body, status, err := c.dpopDo(ctx, key, http.MethodDelete, path, accessToken, "", nil)
	if err != nil {
		return err
	}
	if status != http.StatusNoContent {
		return &Error{Status: status, Body: string(body)}
	}

	return nil
}
