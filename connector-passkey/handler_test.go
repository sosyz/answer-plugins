/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package passkey

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/apache/answer-plugins/connector-passkey/internal/rp"
	"github.com/apache/answer-plugins/connector-passkey/internal/service"
	"github.com/apache/answer-plugins/connector-passkey/internal/store/storetest"
	"github.com/apache/answer-plugins/connector-passkey/internal/webauthntest"
	"github.com/apache/answer/plugin"
	"github.com/gin-gonic/gin"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

const (
	testSite   = "https://example.com"
	testOrigin = "https://example.com"
	userHeader = "X-Test-User"
)

func setEnabled(t *testing.T, enabled bool) {
	t.Helper()
	raw, _ := json.Marshal(map[string]bool{slugName: enabled})
	if err := json.Unmarshal(raw, &plugin.StatusManager); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = json.Unmarshal([]byte(`{}`), &plugin.StatusManager) })
}

// newTestConnector returns an enabled connector on an in-memory store.
func newTestConnector(t *testing.T) *Connector {
	t.Helper()
	gin.SetMode(gin.TestMode)
	setEnabled(t, true)
	setSiteURL(t, testSite)
	w, err := rp.Settings{Name: "Example", ID: "example.com", Origins: []string{testOrigin}}.WebAuthn()
	if err != nil {
		t.Fatal(err)
	}
	c := &Connector{}
	c.svc.Store(service.New(service.Config{
		Store:        storetest.NewMemory(),
		RelyingParty: func() (*webauthn.WebAuthn, error) { return w, nil },
		ReceiverURL:  receiverURL,
	}))
	return c
}

// router mounts the agent routes like the core does; the authenticated group
// gets a stand-in for the core auth middleware that stores the user the way
// answer's middleware does.
func router(c *Connector) *gin.Engine {
	r := gin.New()
	c.RegisterUnAuthRouter(r.Group("/answer/api/v1"))
	auth := r.Group("/answer/api/v1", func(ctx *gin.Context) {
		if id := ctx.GetHeader(userHeader); id != "" {
			ctx.Set("ctxUuidKey", &fakeUserCacheInfo{UserID: id})
		}
	})
	c.RegisterAuthUserRouter(auth)
	c.RegisterAuthAdminRouter(r.Group("/answer/admin/api"))
	return r
}

type envelope struct {
	Code   int             `json:"code"`
	Reason string          `json:"reason"`
	Msg    string          `json:"msg"`
	Data   json.RawMessage `json:"data"`
}

func call(t *testing.T, r http.Handler, method, path, user string, body any) (int, envelope) {
	t.Helper()
	var rd *bytes.Reader
	switch b := body.(type) {
	case nil:
		rd = bytes.NewReader(nil)
	case []byte:
		rd = bytes.NewReader(b)
	default:
		raw, err := json.Marshal(b)
		if err != nil {
			t.Fatal(err)
		}
		rd = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, path, rd)
	req.Header.Set("Content-Type", "application/json")
	if user != "" {
		req.Header.Set(userHeader, user)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	var env envelope
	if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
		t.Fatalf("%s %s: non-JSON response %q", method, path, w.Body.String())
	}
	if env.Code != w.Code {
		t.Fatalf("%s %s: envelope code %d != status %d", method, path, env.Code, w.Code)
	}
	return w.Code, env
}

func dataMap(t *testing.T, env envelope) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(env.Data, &m); err != nil {
		t.Fatalf("data %s: %v", env.Data, err)
	}
	return m
}

func keysOf(m map[string]any) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return strings.Join(sortStrings(keys), ",")
}

func sortStrings(s []string) []string {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
	return s
}

func TestHandlersEndToEnd(t *testing.T) {
	c := newTestConnector(t)
	r := router(c)
	a := webauthntest.New(t, testOrigin)

	// register/begin
	status, env := call(t, r, http.MethodPost, "/answer/api/v1/passkey/register/begin", "u1",
		map[string]string{"user_name": "alice", "display_name": "Alice"})
	if status != 200 || env.Reason != "success" {
		t.Fatalf("register/begin = %d %+v", status, env)
	}
	d := dataMap(t, env)
	if keysOf(d) != "options,session" {
		t.Fatalf("register/begin data keys = %s", keysOf(d))
	}
	opts := d["options"].(map[string]any)
	if _, wrapped := opts["publicKey"]; wrapped {
		t.Fatal("options must not be wrapped in publicKey")
	}
	sel := opts["authenticatorSelection"].(map[string]any)
	if opts["challenge"] == "" || opts["attestation"] != "none" || sel["residentKey"] != "required" ||
		sel["requireResidentKey"] != true || sel["userVerification"] != "required" || opts["timeout"] != float64(300000) {
		t.Fatalf("creation options = %v", opts)
	}
	user := opts["user"].(map[string]any)
	if user["name"] != "alice" || user["displayName"] != "Alice" {
		t.Fatalf("user entity = %v", user)
	}
	var creation protocol.PublicKeyCredentialCreationOptions
	raw, _ := json.Marshal(opts)
	if err := json.Unmarshal(raw, &creation); err != nil {
		t.Fatal(err)
	}

	// register/finish
	status, env = call(t, r, http.MethodPost, "/answer/api/v1/passkey/register/finish", "u1", map[string]any{
		"session": d["session"], "name": "Laptop", "credential": json.RawMessage(a.Create(creation)),
	})
	if status != 200 {
		t.Fatalf("register/finish = %d %+v", status, env)
	}
	d = dataMap(t, env)
	if keysOf(d) != "credential,redirect_url" || d["redirect_url"] != "" {
		t.Fatalf("register/finish data = %v", d)
	}
	cred := d["credential"].(map[string]any)
	credID := base64.RawURLEncoding.EncodeToString(a.CredentialID)
	if keysOf(cred) != "backup_eligible,backup_state,created_at,id,last_used_at,name" ||
		cred["id"] != credID || cred["name"] != "Laptop" || cred["last_used_at"] != nil || cred["backup_state"] != true {
		t.Fatalf("credential view = %v", cred)
	}
	if !strings.HasSuffix(cred["created_at"].(string), "Z") {
		t.Fatalf("created_at not UTC RFC 3339: %v", cred["created_at"])
	}

	// login/begin without a state proof is refused: the state could come
	// from a crafted link.
	status, env = call(t, r, http.MethodPost, "/answer/api/v1/passkey/login/begin", "", map[string]string{"state": "S 1"})
	if status != 400 || env.Reason != "state_unverified" {
		t.Fatalf("login/begin without proof = %d %+v", status, env)
	}

	// login/begin + login/finish
	proof, err := c.svc.Load().LoginStateProof(t.Context(), "S 1")
	if err != nil {
		t.Fatal(err)
	}
	status, env = call(t, r, http.MethodPost, "/answer/api/v1/passkey/login/begin", "", map[string]string{"state": "S 1", "state_proof": proof})
	if status != 200 {
		t.Fatalf("login/begin = %d %+v", status, env)
	}
	d = dataMap(t, env)
	lopts := d["options"].(map[string]any)
	if _, ok := lopts["allowCredentials"]; ok || lopts["userVerification"] != "required" || lopts["challenge"] == "" {
		t.Fatalf("request options = %v", lopts)
	}
	var request protocol.PublicKeyCredentialRequestOptions
	raw, _ = json.Marshal(lopts)
	if err := json.Unmarshal(raw, &request); err != nil {
		t.Fatal(err)
	}
	a.Counter = 1
	status, env = call(t, r, http.MethodPost, "/answer/api/v1/passkey/login/finish", "", map[string]any{
		"session": d["session"], "credential": json.RawMessage(a.Get(request)),
	})
	if status != 200 {
		t.Fatalf("login/finish = %d %+v", status, env)
	}
	d = dataMap(t, env)
	redirect, _ := d["redirect_url"].(string)
	const prefix = "https://example.com/answer/api/v1/connector/redirect/passkey?state=S+1&token="
	if keysOf(d) != "redirect_url" || !strings.HasPrefix(redirect, prefix) {
		t.Fatalf("login/finish data = %v", d)
	}

	// The core receiver redeems the token with the state.
	info := receive(t, c, redirect)
	if info.ExternalID != base64.RawURLEncoding.EncodeToString(a.UserHandle) || info.Email != "" || info.Username != "" || info.DisplayName != "" {
		t.Fatalf("receiver = %+v", info)
	}

	// credentials list
	status, env = call(t, r, http.MethodGet, "/answer/api/v1/passkey/credentials", "u1", nil)
	d = dataMap(t, env)
	list := d["credentials"].([]any)
	if status != 200 || len(list) != 1 || list[0].(map[string]any)["last_used_at"] == nil || list[0].(map[string]any)["id"] != credID {
		t.Fatalf("credentials = %d %v", status, d)
	}
	status, env = call(t, r, http.MethodGet, "/answer/api/v1/passkey/credentials", "u2", nil)
	if d = dataMap(t, env); status != 200 || len(d["credentials"].([]any)) != 0 {
		t.Fatalf("credentials for new user = %d %v", status, d)
	}

	// rename
	status, env = call(t, r, http.MethodPatch, "/answer/api/v1/passkey/credentials/"+credID, "u1", map[string]string{"name": "Phone"})
	if d = dataMap(t, env); status != 200 || d["credential"].(map[string]any)["name"] != "Phone" {
		t.Fatalf("rename = %d %v", status, d)
	}
	status, env = call(t, r, http.MethodPatch, "/answer/api/v1/passkey/credentials/"+credID, "u1", map[string]string{"name": " "})
	if status != 400 || env.Reason != "invalid_name" {
		t.Fatalf("empty rename = %d %+v", status, env)
	}

	// delete: foreign, malformed, own
	status, env = call(t, r, http.MethodDelete, "/answer/api/v1/passkey/credentials/"+credID, "u2", nil)
	if status != 404 || env.Reason != "credential_not_found" {
		t.Fatalf("foreign delete = %d %+v", status, env)
	}
	status, env = call(t, r, http.MethodDelete, "/answer/api/v1/passkey/credentials/not*base64", "u1", nil)
	if status != 400 || env.Reason != "bad_request" {
		t.Fatalf("malformed id = %d %+v", status, env)
	}
	status, env = call(t, r, http.MethodDelete, "/answer/api/v1/passkey/credentials/"+credID, "u1", nil)
	if status != 200 || string(env.Data) != "null" {
		t.Fatalf("delete = %d %+v", status, env)
	}
}

func receive(t *testing.T, c *Connector, redirect string) plugin.ExternalLoginUserInfo {
	t.Helper()
	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ctx.Request = httptest.NewRequest(http.MethodGet, redirect, nil)
	info, err := c.ConnectorReceiver(ctx, "ignored")
	if err != nil {
		t.Fatalf("ConnectorReceiver: %v", err)
	}
	return info
}

func TestBindEndToEnd(t *testing.T) {
	c := newTestConnector(t)
	r := router(c)
	a := webauthntest.New(t, testOrigin)

	// No passkeys yet.
	status, env := call(t, r, http.MethodPost, "/answer/api/v1/passkey/bind/begin", "u1", map[string]string{"state": "B"})
	if status != 404 || env.Reason != "credential_not_found" {
		t.Fatalf("bind/begin without passkeys = %d %+v", status, env)
	}
	status, env = call(t, r, http.MethodPost, "/answer/api/v1/passkey/bind/begin", "u1", map[string]string{})
	if status != 400 || env.Reason != "state_required" {
		t.Fatalf("bind/begin without state = %d %+v", status, env)
	}

	// Register with state: the finish response carries the bind redirect.
	_, env = call(t, r, http.MethodPost, "/answer/api/v1/passkey/register/begin", "u1", map[string]string{"user_name": "alice", "state": "B"})
	d := dataMap(t, env)
	var creation protocol.PublicKeyCredentialCreationOptions
	raw, _ := json.Marshal(d["options"])
	_ = json.Unmarshal(raw, &creation)
	status, env = call(t, r, http.MethodPost, "/answer/api/v1/passkey/register/finish", "u1", map[string]any{
		"session": d["session"], "name": "", "credential": json.RawMessage(a.Create(creation)),
	})
	d = dataMap(t, env)
	if status != 200 || !strings.HasPrefix(d["redirect_url"].(string), "https://example.com/answer/api/v1/connector/redirect/passkey?state=B&token=") {
		t.Fatalf("register/finish with state = %d %v", status, d)
	}

	// Use the existing passkey.
	_, env = call(t, r, http.MethodPost, "/answer/api/v1/passkey/bind/begin", "u1", map[string]string{"state": "B2"})
	d = dataMap(t, env)
	allow := d["options"].(map[string]any)["allowCredentials"].([]any)
	if len(allow) != 1 {
		t.Fatalf("allowCredentials = %v", allow)
	}
	var request protocol.PublicKeyCredentialRequestOptions
	raw, _ = json.Marshal(d["options"])
	_ = json.Unmarshal(raw, &request)
	status, env = call(t, r, http.MethodPost, "/answer/api/v1/passkey/bind/finish", "u1", map[string]any{
		"session": d["session"], "credential": json.RawMessage(a.Get(request)),
	})
	d = dataMap(t, env)
	if status != 200 {
		t.Fatalf("bind/finish = %d %+v", status, env)
	}
	info := receive(t, c, d["redirect_url"].(string))
	if info.ExternalID == "" || info.Email != "" {
		t.Fatalf("receiver = %+v", info)
	}
}

func TestHandlerInputErrors(t *testing.T) {
	c := newTestConnector(t)
	r := router(c)

	big := []byte(`{"state":"` + strings.Repeat("x", 70<<10) + `"}`)
	if status, env := call(t, r, http.MethodPost, "/answer/api/v1/passkey/login/begin", "", big); status != 400 || env.Reason != "bad_request" {
		t.Fatalf("oversized body = %d %+v", status, env)
	}
	for _, tc := range []struct {
		path   string
		user   string
		body   any
		status int
		reason string
	}{
		{"/answer/api/v1/passkey/login/begin", "", []byte(`{`), 400, "bad_request"},
		{"/answer/api/v1/passkey/login/begin", "", []byte(``), 400, "bad_request"},
		{"/answer/api/v1/passkey/login/begin", "", map[string]string{"state": ""}, 400, "state_required"},
		{"/answer/api/v1/passkey/login/finish", "", map[string]string{"session": "x"}, 400, "bad_request"},
		{"/answer/api/v1/passkey/login/finish", "", map[string]any{"session": "", "credential": map[string]string{}}, 400, "bad_request"},
		{"/answer/api/v1/passkey/login/finish", "", map[string]any{"session": "forged", "credential": map[string]string{"id": "x"}}, 400, "session_invalid"},
		{"/answer/api/v1/passkey/register/begin", "", map[string]string{"user_name": "a"}, 401, "unauthorized"},
		{"/answer/api/v1/passkey/register/begin", "u1", map[string]string{"user_name": ""}, 400, "bad_request"},
		{"/answer/api/v1/passkey/register/finish", "u1", map[string]any{"session": "forged", "credential": map[string]string{"id": "x"}}, 400, "session_invalid"},
	} {
		if status, env := call(t, r, http.MethodPost, tc.path, tc.user, tc.body); status != tc.status || env.Reason != tc.reason {
			t.Errorf("POST %s %v = %d %s, want %d %s", tc.path, tc.body, status, env.Reason, tc.status, tc.reason)
		}
	}
	if status, env := call(t, r, http.MethodGet, "/answer/api/v1/passkey/credentials", "", nil); status != 401 || env.Reason != "unauthorized" {
		t.Fatalf("unauthenticated list = %d %+v", status, env)
	}
}
