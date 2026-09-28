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
	"testing"

	"github.com/apache/answer-plugins/connector-passkey/internal/service"
	"github.com/apache/answer-plugins/connector-passkey/internal/store/storetest"
)

func TestGuardDisabled(t *testing.T) {
	c := newTestConnector(t)
	setEnabled(t, false)
	r := router(c)
	for _, tc := range []struct{ method, path, user string }{
		{http.MethodPost, "/answer/api/v1/passkey/login/begin", ""},
		{http.MethodGet, "/answer/api/v1/passkey/credentials", "u1"},
	} {
		status, env := call(t, r, tc.method, tc.path, tc.user, map[string]string{"state": "s"})
		if status != 404 || env.Reason != "plugin_disabled" || string(env.Data) != "null" {
			t.Fatalf("%s %s while disabled = %d %+v", tc.method, tc.path, status, env)
		}
	}
}

func TestGuardNotReady(t *testing.T) {
	newTestConnector(t) // enables the plugin
	c := &Connector{}   // no KV operator attached
	status, env := call(t, router(c), http.MethodPost, "/answer/api/v1/passkey/login/begin", "", map[string]string{"state": "s"})
	if status != 503 || env.Reason != "not_configured" {
		t.Fatalf("login/begin without storage = %d %+v", status, env)
	}
}

// TestNotConfiguredRelyingParty wires the real relyingParty (as SetOperator
// does) with no Site URL and no settings.
func TestNotConfiguredRelyingParty(t *testing.T) {
	newTestConnector(t) // enables the plugin
	setSiteURL(t, "")
	c := &Connector{}
	c.svc.Store(service.New(service.Config{Store: storetest.NewMemory(), RelyingParty: c.relyingParty, ReceiverURL: receiverURL}))
	status, env := call(t, router(c), http.MethodPost, "/answer/api/v1/passkey/login/begin", "", map[string]string{"state": "s"})
	if status != 503 || env.Reason != "not_configured" {
		t.Fatalf("login/begin without RP settings = %d %+v", status, env)
	}
}
