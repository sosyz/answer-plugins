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
	"encoding/base64"
	"net/http"
	"reflect"

	"github.com/gin-gonic/gin"
	"github.com/go-webauthn/webauthn/protocol"
)

// getUserIDFromContext extracts the Answer user ID from Gin context.
// The auth middleware stores user info at context key "ctxUuidKey" as *entity.UserCacheInfo.
// We use reflection because plugins cannot import internal packages.
func getUserIDFromContext(ctx *gin.Context) string {
	val, exists := ctx.Get("ctxUuidKey")
	if !exists || val == nil {
		return ""
	}
	v := reflect.ValueOf(val)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return ""
	}
	f := v.FieldByName("UserID")
	if !f.IsValid() {
		return ""
	}
	return f.String()
}

// handleBeginLogin starts the WebAuthn login ceremony.
// POST /passkey/begin-login
func (c *Connector) handleBeginLogin(ctx *gin.Context) {
	sessionID, options, err := c.beginLogin(ctx.Request.Context())
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{
		"session_id": sessionID,
		"options":    options,
	})
}

// FinishLoginRequest is the request body for the finish-login endpoint.
type FinishLoginRequest struct {
	SessionID string `json:"session_id"`
}

// handleFinishLogin completes the WebAuthn login ceremony.
// POST /passkey/finish-login
func (c *Connector) handleFinishLogin(ctx *gin.Context) {
	// Parse the session_id from query or from a wrapper
	sessionID := ctx.Query("session_id")
	if sessionID == "" {
		// Try to read from a custom header
		sessionID = ctx.GetHeader("X-Session-ID")
	}
	if sessionID == "" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "missing session_id"})
		return
	}

	// Parse the WebAuthn response from the request body
	parsedResponse, err := protocol.ParseCredentialRequestResponseBody(ctx.Request.Body)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "failed to parse credential response: " + err.Error()})
		return
	}

	token, err := c.finishLogin(ctx.Request.Context(), sessionID, parsedResponse)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{
		"token": token,
	})
}

// handleBeginRegister starts the WebAuthn registration ceremony.
// POST /passkey/begin-register
func (c *Connector) handleBeginRegister(ctx *gin.Context) {
	answerUserID := getUserIDFromContext(ctx)
	if answerUserID == "" {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "not authenticated"})
		return
	}

	sessionID, options, err := c.beginRegistration(ctx.Request.Context(), answerUserID)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{
		"session_id": sessionID,
		"options":    options,
	})
}

// FinishRegisterRequest is the request body for the finish-register endpoint.
type FinishRegisterRequest struct {
	SessionID string `json:"session_id"`
	Name      string `json:"name"`
}

// handleFinishRegister completes the WebAuthn registration ceremony.
// POST /passkey/finish-register
func (c *Connector) handleFinishRegister(ctx *gin.Context) {
	sessionID := ctx.Query("session_id")
	if sessionID == "" {
		sessionID = ctx.GetHeader("X-Session-ID")
	}
	name := ctx.Query("name")
	if name == "" {
		name = ctx.GetHeader("X-Passkey-Name")
	}
	if sessionID == "" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "missing session_id"})
		return
	}
	if name == "" {
		name = "My Passkey"
	}

	// Validate passkey name length
	if len(name) > 255 {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "passkey name must be 255 characters or less"})
		return
	}

	parsedResponse, err := protocol.ParseCredentialCreationResponseBody(ctx.Request.Body)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "failed to parse credential response: " + err.Error()})
		return
	}

	err = c.finishRegistration(ctx.Request.Context(), sessionID, name, parsedResponse)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{
		"success": true,
	})
}

// CredentialInfo is the response item for listing credentials.
type CredentialInfo struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	CreatedAt  string `json:"created_at"`
	LastUsedAt string `json:"last_used_at"`
}

// handleListCredentials returns the user's registered passkeys.
// GET /passkey/credentials
func (c *Connector) handleListCredentials(ctx *gin.Context) {
	answerUserID := getUserIDFromContext(ctx)
	if answerUserID == "" {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "not authenticated"})
		return
	}

	externalID, err := c.getOrCreateExternalID(ctx.Request.Context(), answerUserID)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	creds, err := c.getCredentials(ctx.Request.Context(), externalID)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	result := make([]CredentialInfo, len(creds))
	for idx, cred := range creds {
		lastUsed := ""
		if !cred.LastUsedAt.IsZero() {
			lastUsed = cred.LastUsedAt.Format("2006-01-02T15:04:05Z")
		}
		result[idx] = CredentialInfo{
			ID:         base64.RawURLEncoding.EncodeToString(cred.ID),
			Name:       cred.Name,
			CreatedAt:  cred.CreatedAt.Format("2006-01-02T15:04:05Z"),
			LastUsedAt: lastUsed,
		}
	}

	ctx.JSON(http.StatusOK, gin.H{
		"credentials": result,
	})
}

// handleDeleteCredential deletes a passkey by its credential ID.
// DELETE /passkey/credentials/:id
func (c *Connector) handleDeleteCredential(ctx *gin.Context) {
	answerUserID := getUserIDFromContext(ctx)
	if answerUserID == "" {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "not authenticated"})
		return
	}

	credIDParam := ctx.Param("id")
	credID, err := base64.RawURLEncoding.DecodeString(credIDParam)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid credential ID"})
		return
	}

	externalID, err := c.getOrCreateExternalID(ctx.Request.Context(), answerUserID)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	err = c.deleteCredential(ctx.Request.Context(), externalID, credID)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{
		"success": true,
	})
}
