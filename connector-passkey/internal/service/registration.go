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

package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/apache/answer-plugins/connector-passkey/internal/store"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// newUserHandle returns 32 random bytes, base64url encoded. The handle is the
// WebAuthn user.id and the core ExternalID.
func newUserHandle() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// BeginRegistration starts creating a passkey for a logged-in Answer user.
// A non-empty state (core bind intent) makes FinishRegistration return a
// redirect URL that links the passkey to the account.
func (s *Service) BeginRegistration(ctx context.Context, answerUserID string, label UserLabel, state string) (RegistrationCeremony, error) {
	if answerUserID == "" {
		return RegistrationCeremony{}, ErrInvalidInput
	}
	if err := checkState(state); err != nil {
		return RegistrationCeremony{}, err
	}
	name, err := sanitizeLabel(label.Name, true)
	if err != nil {
		return RegistrationCeremony{}, fmt.Errorf("%w: user_name", ErrInvalidInput)
	}
	displayName, err := sanitizeLabel(label.DisplayName, false)
	if err != nil {
		return RegistrationCeremony{}, fmt.Errorf("%w: display_name", ErrInvalidInput)
	}
	if displayName == "" {
		displayName = name
	}
	w, err := s.rp()
	if err != nil {
		return RegistrationCeremony{}, err
	}

	handle, err := s.store.EnsureUserHandle(ctx, answerUserID, newUserHandle)
	if err != nil {
		return RegistrationCeremony{}, fmt.Errorf("passkey: user handle: %w", err)
	}
	handleBytes, err := decodeHandle(handle)
	if err != nil {
		return RegistrationCeremony{}, err
	}
	existing, err := s.credentialsOf(ctx, handle)
	if err != nil {
		return RegistrationCeremony{}, err
	}
	if len(existing) >= maxCredentialsPerUser {
		return RegistrationCeremony{}, ErrCredentialLimit
	}

	exclusions := make([]protocol.CredentialDescriptor, 0, len(existing))
	creds := make([]webauthn.Credential, 0, len(existing))
	for _, rec := range existing {
		exclusions = append(exclusions, rec.Credential.Descriptor())
		creds = append(creds, rec.Credential)
	}
	user := &webauthnUser{id: handleBytes, name: name, displayName: displayName, creds: creds}
	creation, data, err := w.BeginRegistration(user, webauthn.WithExclusions(exclusions))
	if err != nil {
		return RegistrationCeremony{}, fmt.Errorf("passkey: begin registration: %w", err)
	}
	sealed, err := s.seal(ctx, s.newState(purposeRegister, answerUserID, handle, state, data))
	if err != nil {
		return RegistrationCeremony{}, err
	}
	return RegistrationCeremony{Session: sealed, Options: creation.Response}, nil
}

// FinishRegistration verifies the authenticator response and stores the new
// passkey. The returned redirect URL is empty unless the ceremony was started
// with a core state.
func (s *Service) FinishRegistration(ctx context.Context, answerUserID, session, name string, response []byte) (Credential, string, error) {
	st, err := s.open(ctx, session, purposeRegister)
	if err != nil {
		return Credential{}, "", err
	}
	if answerUserID == "" || st.UserID != answerUserID {
		return Credential{}, "", ErrSessionInvalid
	}
	handle, err := s.store.UserHandle(ctx, answerUserID)
	if errors.Is(err, store.ErrNotFound) {
		return Credential{}, "", ErrSessionInvalid
	}
	if err != nil {
		return Credential{}, "", fmt.Errorf("passkey: user handle: %w", err)
	}
	if handle != st.Handle {
		return Credential{}, "", ErrSessionInvalid
	}
	if err := s.checkNotConsumed(ctx, st.Data.Challenge); err != nil {
		return Credential{}, "", err
	}
	name, err = sanitizeLabel(name, false)
	if err != nil {
		return Credential{}, "", ErrInvalidName
	}
	existing, err := s.credentialsOf(ctx, handle)
	if err != nil {
		return Credential{}, "", err
	}
	if len(existing) >= maxCredentialsPerUser {
		return Credential{}, "", ErrCredentialLimit
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(response)
	if err != nil {
		return Credential{}, "", fmt.Errorf("%w: credential", ErrInvalidInput)
	}
	w, err := s.rp()
	if err != nil {
		return Credential{}, "", err
	}
	handleBytes, err := decodeHandle(handle)
	if err != nil {
		return Credential{}, "", err
	}
	creds := make([]webauthn.Credential, 0, len(existing))
	for _, rec := range existing {
		creds = append(creds, rec.Credential)
	}
	cred, err := w.CreateCredential(&webauthnUser{id: handleBytes, creds: creds}, st.Data, parsed)
	if err != nil {
		return Credential{}, "", verificationFailed("registration", err)
	}

	rec := store.CredentialRecord{UserHandle: handle, Name: name, CreatedAt: s.nowUTC(), Credential: *cred}
	token, err := s.saveRegistration(ctx, st, rec)
	if err != nil {
		return Credential{}, "", err
	}
	s.purge(ctx)

	redirect := ""
	if token != "" {
		redirect = s.receiverURL(token, st.State)
	}
	return toView(rec), redirect, nil
}

// saveRegistration is the locked part of FinishRegistration: it re-checks
// single use, the per-user limit and credential uniqueness right before the
// transaction (lock order: challenge, user handle, credential) and returns
// the raw login token, if the ceremony carries a core state.
func (s *Service) saveRegistration(ctx context.Context, st ceremonyState, rec store.CredentialRecord) (string, error) {
	unlockChallenge := s.challengeLocks.lock(st.Data.Challenge)
	defer unlockChallenge()
	if err := s.checkNotConsumed(ctx, st.Data.Challenge); err != nil {
		return "", err
	}
	// Registrations of the same user with different challenges and
	// credentials would otherwise not serialize, and could exceed the limit.
	unlockHandle := s.handleLocks.lock(rec.UserHandle)
	defer unlockHandle()
	owned, err := s.credentialsOf(ctx, rec.UserHandle)
	if err != nil {
		return "", err
	}
	if len(owned) >= maxCredentialsPerUser {
		return "", ErrCredentialLimit
	}
	id := rec.Credential.ID
	unlockCredential := s.credentialLocks.lock(store.CredentialKey(id))
	defer unlockCredential()
	// WebAuthn §7.1 step 22: a credential ID registered to any user is rejected.
	if _, err := s.store.Credential(ctx, id); err == nil {
		return "", ErrCredentialExists
	} else if !errors.Is(err, store.ErrNotFound) {
		return "", fmt.Errorf("passkey: credential lookup: %w", err)
	}

	result := store.CeremonyResult{
		Challenge:          st.Data.Challenge,
		ChallengeExpiresAt: s.consumedUntil(st),
		Credential:         rec,
		NewCredential:      true,
	}
	var token string
	if st.State != "" {
		token, result.TokenHash, result.Token, err = s.newLoginToken(rec.UserHandle, st.State)
		if err != nil {
			return "", err
		}
	}
	if err := s.store.SaveCeremonyResult(ctx, result); err != nil {
		ferr := s.saveFailed(ctx, st.Data.Challenge, "save registration", err)
		// The same credential ID registered meanwhile (another instance).
		if !errors.Is(ferr, ErrSessionInvalid) {
			if _, cerr := s.store.Credential(ctx, id); cerr == nil {
				return "", ErrCredentialExists
			}
		}
		return "", ferr
	}
	return token, nil
}
