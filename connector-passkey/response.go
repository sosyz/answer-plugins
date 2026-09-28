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
	"net/http"
	"time"

	"github.com/apache/answer-plugins/connector-passkey/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/segmentfault/pacman/log"
)

// respBody is the Answer core response envelope.
type respBody struct {
	Code   int    `json:"code"`
	Reason string `json:"reason"`
	Msg    string `json:"msg"`
	Data   any    `json:"data"`
}

type errorMapping struct {
	err    error
	status int
	reason string
}

// errorTable maps sentinel errors to HTTP status and reason. The reason is the
// stable contract with the UI (i18n key error.<reason>).
var errorTable = []errorMapping{
	{service.ErrInvalidInput, http.StatusBadRequest, "bad_request"},
	{service.ErrStateRequired, http.StatusBadRequest, "state_required"},
	{service.ErrStateUnverified, http.StatusBadRequest, "state_unverified"},
	{service.ErrSessionInvalid, http.StatusBadRequest, "session_invalid"},
	{service.ErrVerificationFailed, http.StatusBadRequest, "verification_failed"},
	{service.ErrCloneDetected, http.StatusBadRequest, "clone_detected"},
	{service.ErrInvalidName, http.StatusBadRequest, "invalid_name"},
	{service.ErrTokenInvalid, http.StatusBadRequest, "bad_request"},
	{errUnauthorized, http.StatusUnauthorized, "unauthorized"},
	{errPluginDisabled, http.StatusNotFound, "plugin_disabled"},
	{service.ErrCredentialNotFound, http.StatusNotFound, "credential_not_found"},
	{service.ErrCredentialExists, http.StatusConflict, "credential_exists"},
	{service.ErrCredentialLimit, http.StatusConflict, "credential_limit"},
	{service.ErrNotConfigured, http.StatusServiceUnavailable, "not_configured"},
	{errNotReady, http.StatusServiceUnavailable, "not_configured"},
}

func ok(ctx *gin.Context, data any) {
	ctx.JSON(http.StatusOK, respBody{Code: http.StatusOK, Reason: "success", Data: data})
}

// fail writes the error envelope. Unknown errors are logged and reported as
// 500 internal_error without their message.
func fail(ctx *gin.Context, err error) {
	for _, m := range errorTable {
		if errors.Is(err, m.err) {
			if m.status == http.StatusServiceUnavailable {
				log.Warnf("%s %s: %v", ctx.Request.Method, ctx.FullPath(), err)
			}
			ctx.AbortWithStatusJSON(m.status, respBody{Code: m.status, Reason: m.reason, Msg: m.err.Error()})
			return
		}
	}
	log.Errorf("%s %s: %v", ctx.Request.Method, ctx.FullPath(), err)
	ctx.AbortWithStatusJSON(http.StatusInternalServerError, respBody{
		Code: http.StatusInternalServerError, Reason: "internal_error", Msg: "internal error",
	})
}

// credentialView is the JSON form of a passkey.
type credentialView struct {
	ID             string  `json:"id"`
	Name           string  `json:"name"`
	CreatedAt      string  `json:"created_at"`
	LastUsedAt     *string `json:"last_used_at"`
	BackupEligible bool    `json:"backup_eligible"`
	BackupState    bool    `json:"backup_state"`
}

func formatTime(t time.Time) string {
	return t.UTC().Format(time.RFC3339)
}

func toCredentialView(c service.Credential) credentialView {
	v := credentialView{
		ID:             encodeID(c.ID),
		Name:           c.Name,
		CreatedAt:      formatTime(c.CreatedAt),
		BackupEligible: c.BackupEligible,
		BackupState:    c.BackupState,
	}
	if !c.LastUsedAt.IsZero() {
		s := formatTime(c.LastUsedAt)
		v.LastUsedAt = &s
	}
	return v
}
