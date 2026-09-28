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
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/apache/answer-plugins/connector-passkey/internal/service"
	"github.com/apache/answer-plugins/connector-passkey/internal/store"
	"github.com/apache/answer-plugins/connector-passkey/internal/store/storetest"
	"github.com/apache/answer-plugins/connector-passkey/internal/webauthntest"
	"github.com/apache/answer/plugin"
	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v3"
)

var (
	_ plugin.Connector  = (*Connector)(nil)
	_ plugin.Config     = (*Connector)(nil)
	_ plugin.UserConfig = (*Connector)(nil)
	_ plugin.Agent      = (*Connector)(nil)
	_ plugin.KVStorage  = (*Connector)(nil)
)

func TestConstsMatchInfoYAML(t *testing.T) {
	raw, err := os.ReadFile("info.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var info struct {
		SlugName string `yaml:"slug_name"`
		Type     string `yaml:"type"`
		Route    string `yaml:"route"`
		Link     string `yaml:"link"`
	}
	if err := yaml.Unmarshal(raw, &info); err != nil {
		t.Fatal(err)
	}
	if info.SlugName != slugName || info.Route != pageRoute || info.Type != "route" {
		t.Fatalf("info.yaml %+v does not match consts %q %q", info, slugName, pageRoute)
	}
	if !strings.HasSuffix(info.Link, "/tree/main/connector-passkey") {
		t.Fatalf("link = %q", info.Link)
	}
	if got := (&Connector{}).Info(); got.SlugName != slugName {
		t.Fatalf("Info().SlugName = %q", got.SlugName)
	}
	if (&Connector{}).ConnectorSlugName() != connectorSlug {
		t.Fatal("connector slug changed")
	}
}

func TestReceiverURLMatchesCoreRoute(t *testing.T) {
	for _, tc := range []struct{ site, want string }{
		{"https://example.com/community/", "https://example.com/community/answer/api/v1/connector/redirect/passkey"},
		{"https://example.com", "https://example.com/answer/api/v1/connector/redirect/passkey"},
		{"", "/answer/api/v1/connector/redirect/passkey"},
	} {
		setSiteURL(t, tc.site)
		if got := receiverURL(); got != tc.want {
			t.Errorf("receiverURL() with Site URL %q = %q, want %q", tc.site, got, tc.want)
		}
	}
}

// TestSetOperator attaches a real KV operator: the ceremony key is created at
// start-up and the service is wired to the connector settings.
func TestSetOperator(t *testing.T) {
	newTestConnector(t) // enables the plugin, sets the Site URL
	op, engine := storetest.NewSQLiteKV(t, slugName)
	c := &Connector{}
	c.SetOperator(op)
	rows, err := engine.QueryString(`SELECT "group", "key" FROM plugin_kv_storage`)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0]["group"] != store.GroupSecret || rows[0]["key"] != store.KeyCeremony {
		t.Fatalf("rows after SetOperator = %v, want only the ceremony key", rows)
	}
	svc := c.svc.Load()
	if svc == nil {
		t.Fatal("SetOperator did not attach the service")
	}
	proof, err := svc.LoginStateProof(t.Context(), "S")
	if err != nil {
		t.Fatal(err)
	}
	status, env := call(t, router(c), http.MethodPost, "/answer/api/v1/passkey/login/begin", "", map[string]string{"state": "S", "state_proof": proof})
	if status != 200 {
		t.Fatalf("login/begin = %d %+v", status, env)
	}
	if rows, _ := engine.QueryString(`SELECT "key" FROM plugin_kv_storage`); len(rows) != 1 {
		t.Fatalf("login/begin wrote rows: %v", rows)
	}
}

func senderCtx(rawQuery string) *gin.Context {
	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ctx.Request = httptest.NewRequest(http.MethodGet, "/answer/api/v1/connector/login/passkey?"+rawQuery, nil)
	return ctx
}

func TestConnectorSender(t *testing.T) {
	c := newTestConnector(t)
	setSiteURL(t, "https://example.com/community")
	page := "https://example.com/community/connector-passkey-auth"
	proof := func(state string) string {
		t.Helper()
		p, err := c.svc.Load().LoginStateProof(t.Context(), state)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	// coreLogin mimics the core ConnectorLogin: it reads ctx.Query("state")
	// (filling gin's query cache), and when that is empty generates a login
	// state and rewrites RawQuery, leaving the cache stale.
	coreLogin := func(rawQuery, generated string) *gin.Context {
		ctx := senderCtx(rawQuery)
		if ctx.Query("state") == "" {
			q := ctx.Request.URL.Query()
			q.Set("state", generated)
			ctx.Request.URL.RawQuery = q.Encode()
		}
		return ctx
	}

	// A state the core has just generated gets a proof.
	got := c.ConnectorSender(coreLogin("", "gen 1"), "https://ignored/receiver")
	want := page + "?" + url.Values{"state": {"gen 1"}, "state_proof": {proof("gen 1")}}.Encode()
	if got != want {
		t.Fatalf("sender for generated state = %q, want %q", got, want)
	}

	// A state supplied by the caller (a bind state or a crafted link) is
	// forwarded without a proof.
	if got := c.ConnectorSender(coreLogin("state="+url.QueryEscape("a b&c"), "unused"), ""); got != page+"?state=a+b%26c" {
		t.Fatalf("sender for caller state = %q", got)
	}

	// ?state=&state=S_A: gin's first value is empty, so the core generates a
	// state and q.Set replaces both; the proof is for the generated state.
	got = c.ConnectorSender(coreLogin("state=&state=attacker", "gen 2"), "")
	want = page + "?" + url.Values{"state": {"gen 2"}, "state_proof": {proof("gen 2")}}.Encode()
	if got != want {
		t.Fatalf("sender for duplicated state = %q, want %q", got, want)
	}

	if got := c.ConnectorSender(senderCtx("receiver=https://evil.example"), ""); got != page+"?state=" {
		t.Fatalf("sender without state = %q", got)
	}

	// Not initialized yet: no proof, no panic.
	if got := (&Connector{}).ConnectorSender(coreLogin("", "gen 3"), ""); got != page+"?state=gen+3" {
		t.Fatalf("sender before init = %q", got)
	}
}

func TestConnectorReceiver(t *testing.T) {
	c := newTestConnector(t)
	svc := c.svc.Load()
	a := webauthntest.New(t, testOrigin)
	ctx := t.Context()

	cer, err := svc.BeginRegistration(ctx, "u1", service.UserLabel{Name: "alice"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.FinishRegistration(ctx, "u1", cer.Session, "", a.Create(cer.Options)); err != nil {
		t.Fatal(err)
	}
	login := func(state string) (token string) {
		t.Helper()
		proof, err := svc.LoginStateProof(ctx, state)
		if err != nil {
			t.Fatal(err)
		}
		lc, err := svc.BeginLogin(ctx, state, proof)
		if err != nil {
			t.Fatal(err)
		}
		a.Counter++
		redirect, err := svc.FinishLogin(ctx, lc.Session, a.Get(lc.Options))
		if err != nil {
			t.Fatal(err)
		}
		u, _ := url.Parse(redirect)
		return u.Query().Get("token")
	}
	recv := func(q url.Values) (plugin.ExternalLoginUserInfo, error) {
		rctx, _ := gin.CreateTestContext(httptest.NewRecorder())
		rctx.Request = httptest.NewRequest(http.MethodGet, "/answer/api/v1/connector/redirect/passkey?"+q.Encode(), nil)
		return c.ConnectorReceiver(rctx, "")
	}

	if _, err := recv(url.Values{"token": {login("S")}}); err == nil {
		t.Fatal("receiver accepted a token without state")
	}
	if _, err := recv(url.Values{"token": {login("S")}, "state": {"other"}}); err == nil {
		t.Fatal("receiver accepted a token with the wrong state")
	}
	if _, err := recv(url.Values{"state": {"S"}}); err == nil {
		t.Fatal("receiver accepted a missing token")
	}
	info, err := recv(url.Values{"token": {login("S")}, "state": {"S"}})
	if err != nil {
		t.Fatal(err)
	}
	// Intent of 63de52c: only the opaque user handle is returned; no address
	// or profile data that the core could use for automatic account binding.
	if info.ExternalID == "" || info.Email != "" || info.Username != "" || info.DisplayName != "" || info.Avatar != "" || info.MetaInfo != "" {
		t.Fatalf("receiver returned %+v", info)
	}

	if _, err := (&Connector{}).ConnectorReceiver(senderCtx(""), ""); err == nil {
		t.Fatal("receiver without storage must fail")
	}
}
