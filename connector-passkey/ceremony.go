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
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

const (
	sessionTypeRegister = "register"
	sessionTypeLogin    = "login"
)

// RegisterSession stores the WebAuthn session along with the user external ID for registration.
type RegisterSession struct {
	SessionData    *webauthn.SessionData `json:"session_data"`
	UserExternalID string                `json:"user_external_id"`
}

// beginRegistration starts a WebAuthn registration ceremony for a user.
func (c *Connector) beginRegistration(ctx context.Context, answerUserID string) (sessionID string, options *protocol.CredentialCreation, err error) {
	w := c.getWebAuthn()
	if w == nil {
		return "", nil, fmt.Errorf("WebAuthn not configured")
	}

	externalID, err := c.getOrCreateExternalID(ctx, answerUserID)
	if err != nil {
		return "", nil, err
	}

	// Load existing credentials to exclude them
	existing, err := c.getCredentials(ctx, externalID)
	if err != nil {
		return "", nil, err
	}

	user := &PasskeyUser{
		ID:          []byte(externalID),
		DisplayName: answerUserID,
		Credentials: storedToWebAuthnCredentials(existing),
	}

	excludeList := make([]protocol.CredentialDescriptor, len(existing))
	for idx, cred := range existing {
		transports := make([]protocol.AuthenticatorTransport, len(cred.Transport))
		for j, t := range cred.Transport {
			transports[j] = protocol.AuthenticatorTransport(t)
		}
		excludeList[idx] = protocol.CredentialDescriptor{
			Type:            protocol.PublicKeyCredentialType,
			CredentialID:    cred.ID,
			Transport:       transports,
		}
	}

	opts := []webauthn.RegistrationOption{
		webauthn.WithExclusions(excludeList),
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
	}

	creation, session, err := w.BeginRegistration(user, opts...)
	if err != nil {
		return "", nil, fmt.Errorf("failed to begin registration: %w", err)
	}

	// Store session with user external ID
	regSession := RegisterSession{
		SessionData:    session,
		UserExternalID: externalID,
	}
	sessionBytes, err := json.Marshal(regSession)
	if err != nil {
		return "", nil, err
	}

	sessionID, err = c.saveSession(ctx, sessionTypeRegister, sessionBytes)
	if err != nil {
		return "", nil, err
	}

	return sessionID, creation, nil
}

// finishRegistration completes the WebAuthn registration ceremony.
func (c *Connector) finishRegistration(ctx context.Context, sessionID string, name string, response *protocol.ParsedCredentialCreationData) error {
	w := c.getWebAuthn()
	if w == nil {
		return fmt.Errorf("WebAuthn not configured")
	}

	sd, err := c.consumeSession(ctx, sessionID, sessionTypeRegister)
	if err != nil {
		return err
	}

	var regSession RegisterSession
	if err := json.Unmarshal(sd.Data, &regSession); err != nil {
		return fmt.Errorf("failed to unmarshal register session: %w", err)
	}

	// Load the user
	existing, err := c.getCredentials(ctx, regSession.UserExternalID)
	if err != nil {
		return err
	}

	user := &PasskeyUser{
		ID:          []byte(regSession.UserExternalID),
		DisplayName: regSession.UserExternalID,
		Credentials: storedToWebAuthnCredentials(existing),
	}

	credential, err := w.CreateCredential(user, *regSession.SessionData, response)
	if err != nil {
		return fmt.Errorf("failed to create credential: %w", err)
	}

	stored := webauthnToStoredCredential(credential, name)
	stored.CreatedAt = time.Now()

	return c.addCredential(ctx, regSession.UserExternalID, stored)
}

// beginLogin starts a WebAuthn discoverable login ceremony.
func (c *Connector) beginLogin(ctx context.Context) (sessionID string, options *protocol.CredentialAssertion, err error) {
	w := c.getWebAuthn()
	if w == nil {
		return "", nil, fmt.Errorf("WebAuthn not configured")
	}

	assertion, session, err := w.BeginDiscoverableLogin(
		webauthn.WithUserVerification(protocol.VerificationRequired),
	)
	if err != nil {
		return "", nil, fmt.Errorf("failed to begin login: %w", err)
	}

	sessionBytes, err := json.Marshal(session)
	if err != nil {
		return "", nil, err
	}

	sessionID, err = c.saveSession(ctx, sessionTypeLogin, sessionBytes)
	if err != nil {
		return "", nil, err
	}

	return sessionID, assertion, nil
}

// finishLogin completes the WebAuthn login ceremony and returns a one-time token.
func (c *Connector) finishLogin(ctx context.Context, sessionID string, response *protocol.ParsedCredentialAssertionData) (string, error) {
	w := c.getWebAuthn()
	if w == nil {
		return "", fmt.Errorf("WebAuthn not configured")
	}

	sd, err := c.consumeSession(ctx, sessionID, sessionTypeLogin)
	if err != nil {
		return "", err
	}

	var session webauthn.SessionData
	if err := json.Unmarshal(sd.Data, &session); err != nil {
		return "", fmt.Errorf("failed to unmarshal login session: %w", err)
	}

	// Discoverable login handler: resolves userHandle to a user
	handler := func(rawID, userHandle []byte) (webauthn.User, error) {
		userExternalID := string(userHandle)

		creds, err := c.getCredentials(ctx, userExternalID)
		if err != nil {
			return nil, fmt.Errorf("user not found for handle: %w", err)
		}
		if len(creds) == 0 {
			return nil, fmt.Errorf("no credentials found for user")
		}

		return &PasskeyUser{
			ID:          userHandle,
			DisplayName: userExternalID,
			Credentials: storedToWebAuthnCredentials(creds),
		}, nil
	}

	credential, err := w.ValidateDiscoverableLogin(handler, session, response)
	if err != nil {
		return "", fmt.Errorf("failed to validate login: %w", err)
	}

	// Find which user owns this credential
	userExternalID, err := c.lookupUserByCredentialID(ctx, credential.ID)
	if err != nil {
		return "", fmt.Errorf("failed to find credential owner: %w", err)
	}

	// Update sign count and last-used
	_ = c.updateCredentialUsage(ctx, userExternalID, credential.ID, credential.Authenticator.SignCount)

	// Create a one-time login token
	token, err := c.createToken(ctx, userExternalID)
	if err != nil {
		return "", fmt.Errorf("failed to create login token: %w", err)
	}

	return token, nil
}
