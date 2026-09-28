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
	"errors"
	"maps"
	"net/http"
	"testing"

	"github.com/apache/answer-plugins/connector-passkey/internal/rp"
	"github.com/apache/answer-plugins/connector-passkey/internal/service"
	"github.com/apache/answer-plugins/connector-passkey/internal/store/storetest"
	"github.com/apache/answer/plugin"
)

func setSiteURL(t *testing.T, site string) {
	t.Helper()
	plugin.RegisterGetSiteURLFunc(func() string { return site })
	t.Cleanup(func() { plugin.RegisterGetSiteURLFunc(func() string { return "" }) })
}

func TestConfigFields(t *testing.T) {
	setSiteURL(t, "https://example.com")
	c := &Connector{}
	if err := c.ConfigReceiver([]byte(`{"rp_name":" Q&A ","rp_id":"Example.com","rp_origins":"https://example.com/","attestation_type":"direct"}`)); err != nil {
		t.Fatal(err)
	}
	fields := c.ConfigFields()
	want := map[string]any{"rp_name": "Q&A", "rp_id": "example.com", "rp_origins": "https://example.com/"}
	if len(fields) != len(want) {
		t.Fatalf("got %d fields", len(fields))
	}
	for _, f := range fields {
		if v, ok := want[f.Name]; !ok || f.Value != v || f.Required || f.Type != plugin.ConfigTypeInput {
			t.Errorf("field %s = %+v", f.Name, f)
		}
	}
}

func fieldValues(c *Connector) map[string]any {
	out := map[string]any{}
	for _, f := range c.ConfigFields() {
		out[f.Name] = f.Value
	}
	return out
}

func TestConfigReceiver(t *testing.T) {
	setSiteURL(t, "https://example.com/community")
	c := &Connector{}
	router(c) // the core mounts the routes after start-up: this is an admin save
	if err := c.ConfigReceiver([]byte(`{}`)); err != nil {
		t.Fatalf("empty config: %v", err)
	}
	w, err := c.relyingParty()
	if err != nil {
		t.Fatal(err)
	}
	if w.Config.RPID != "example.com" || w.Config.RPDisplayName != "example.com" || len(w.Config.RPOrigins) != 1 || w.Config.RPOrigins[0] != "https://example.com" {
		t.Fatalf("defaults = %+v", w.Config)
	}

	if err := c.ConfigReceiver([]byte(`{"rp_origins":"https://qa.example.com"}`)); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{
		`{"rp_origins":"http://example.com"}`,
		`{"rp_origins":"https://example.org"}`,
		`{"rp_id":"example.com:8443"}`,
		`not json`,
	} {
		if err := c.ConfigReceiver([]byte(bad)); err == nil {
			t.Errorf("ConfigReceiver(%s) accepted", bad)
		}
	}
	if w, err := c.relyingParty(); err != nil || w.Config.RPOrigins[0] != "https://qa.example.com" {
		t.Fatalf("rejected config replaced the valid one: %v %v", w, err)
	}
	if got := fieldValues(c); got["rp_origins"] != "https://qa.example.com" || got["rp_id"] != "" {
		t.Fatalf("rejected config is shown: %v", got)
	}
}

// TestConfigLoadedInvalid covers settings that were valid when saved but no
// longer are at start-up (here the Site URL moved to another domain).
func TestConfigLoadedInvalid(t *testing.T) {
	c := newTestConnector(t)
	setSiteURL(t, "https://other.example.org")
	c.svc.Store(service.New(service.Config{Store: storetest.NewMemory(), RelyingParty: c.relyingParty, ReceiverURL: receiverURL}))
	stored := `{"rp_name":"Q&A","rp_id":"","rp_origins":"https://example.com"}`

	// Start-up: the core passes the stored row before mounting the routes.
	err := c.ConfigReceiver([]byte(stored))
	if err == nil {
		t.Fatal("invalid stored settings were accepted silently")
	}
	want := map[string]any{"rp_name": "Q&A", "rp_id": "", "rp_origins": "https://example.com"}
	if got := fieldValues(c); !maps.Equal(got, want) {
		t.Fatalf("ConfigFields = %v, want the stored %v", got, want)
	}
	if _, err := c.relyingParty(); !errors.Is(err, rp.ErrNotConfigured) {
		t.Fatalf("relyingParty() = %v, want ErrNotConfigured", err)
	}

	r := router(c)
	status, env := call(t, r, http.MethodPost, "/answer/api/v1/passkey/login/begin", "", map[string]string{"state": "s", "state_proof": "p"})
	if status != 503 || env.Reason != "not_configured" {
		t.Fatalf("login/begin with invalid stored settings = %d %+v", status, env)
	}

	// Admin saves: invalid ones are rejected and change nothing.
	if err := c.ConfigReceiver([]byte(`{"rp_id":"example.com:8443"}`)); err == nil {
		t.Fatal("invalid admin save accepted")
	}
	if got := fieldValues(c); !maps.Equal(got, want) {
		t.Fatalf("rejected save changed ConfigFields: %v", got)
	}
	if err := c.ConfigReceiver([]byte(`{"rp_name":"Q&A"}`)); err != nil {
		t.Fatal(err)
	}
	if w, err := c.relyingParty(); err != nil || w.Config.RPID != "other.example.org" {
		t.Fatalf("relyingParty() after a valid save = %v, %v", w, err)
	}
}

func TestConfigLoadedUndecodable(t *testing.T) {
	setSiteURL(t, "https://example.com")
	c := &Connector{}
	if err := c.ConfigReceiver([]byte(`{"rp_id":42}`)); err == nil {
		t.Fatal("undecodable stored settings accepted")
	}
	if _, err := c.relyingParty(); !errors.Is(err, rp.ErrNotConfigured) {
		t.Fatalf("relyingParty() = %v, want ErrNotConfigured instead of Site URL defaults", err)
	}
	router(c)
	if err := c.ConfigReceiver([]byte(`not json`)); err == nil {
		t.Fatal("undecodable admin save accepted")
	}
	if _, err := c.relyingParty(); !errors.Is(err, rp.ErrNotConfigured) {
		t.Fatalf("rejected admin save cleared the load error: %v", err)
	}
	if err := c.ConfigReceiver([]byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.relyingParty(); err != nil {
		t.Fatalf("relyingParty() after a valid save = %v", err)
	}
}

// Without a stored row the core never calls ConfigReceiver: the Site URL
// defaults apply.
func TestConfigNoStoredRow(t *testing.T) {
	setSiteURL(t, "https://example.com")
	if w, err := (&Connector{}).relyingParty(); err != nil || w.Config.RPID != "example.com" {
		t.Fatalf("relyingParty() = %v, %v", w, err)
	}
}

func TestRelyingPartyNotConfigured(t *testing.T) {
	setSiteURL(t, "")
	c := &Connector{}
	if err := c.ConfigReceiver([]byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.relyingParty(); !errors.Is(err, rp.ErrNotConfigured) {
		t.Fatalf("relyingParty() = %v, want ErrNotConfigured", err)
	}
}

func TestUserConfigFields(t *testing.T) {
	setSiteURL(t, "https://example.com/community/")
	fields := (&Connector{}).UserConfigFields()
	if len(fields) != 1 || fields[0].Name != "manage_passkeys" || fields[0].Type != plugin.ConfigTypeButton {
		t.Fatalf("fields = %+v", fields)
	}
	a := fields[0].UIOptions.Action
	if a == nil || a.Url != "https://example.com/community/connector-passkey-auth?mode=manage" || a.Method != "navigate" {
		t.Fatalf("action = %+v", a)
	}
	if err := (&Connector{}).UserConfigReceiver("u1", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
}
