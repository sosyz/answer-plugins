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
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/apache/answer-plugins/connector-passkey/internal/service"
	"github.com/gin-gonic/gin"
)

func TestFailMapsErrors(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, tc := range []struct {
		err    error
		status int
		reason string
	}{
		{service.ErrInvalidInput, 400, "bad_request"},
		{service.ErrStateRequired, 400, "state_required"},
		{service.ErrSessionInvalid, 400, "session_invalid"},
		{service.ErrVerificationFailed, 400, "verification_failed"},
		{service.ErrCloneDetected, 400, "clone_detected"},
		{service.ErrInvalidName, 400, "invalid_name"},
		{service.ErrTokenInvalid, 400, "bad_request"},
		{errUnauthorized, 401, "unauthorized"},
		{errPluginDisabled, 404, "plugin_disabled"},
		{service.ErrCredentialNotFound, 404, "credential_not_found"},
		{service.ErrCredentialExists, 409, "credential_exists"},
		{service.ErrCredentialLimit, 409, "credential_limit"},
		{service.ErrNotConfigured, 503, "not_configured"},
		{errNotReady, 503, "not_configured"},
		{fmt.Errorf("%w: wrapped", service.ErrInvalidInput), 400, "bad_request"},
		{errors.New("pq: password authentication failed for user secret"), 500, "internal_error"},
	} {
		t.Run(tc.reason, func(t *testing.T) {
			w := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(w)
			ctx.Request = httptest.NewRequest(http.MethodGet, "/x", nil)
			fail(ctx, tc.err)
			var body map[string]any
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if w.Code != tc.status || body["code"] != float64(tc.status) || body["reason"] != tc.reason || body["data"] != nil {
				t.Fatalf("fail(%v) = %d %v", tc.err, w.Code, body)
			}
			if msg, _ := body["msg"].(string); strings.Contains(msg, "secret") || strings.Contains(msg, "wrapped") {
				t.Fatalf("msg leaks details: %q", msg)
			}
			if len(body) != 4 {
				t.Fatalf("envelope has extra fields: %v", body)
			}
		})
	}
}

func TestOKEnvelope(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ok(ctx, nil)
	if got := w.Body.String(); got != `{"code":200,"reason":"success","msg":"","data":null}` {
		t.Fatalf("ok envelope = %s", got)
	}
}
