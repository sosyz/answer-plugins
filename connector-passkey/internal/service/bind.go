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
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/apache/answer-plugins/connector-passkey/internal/store"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// BeginBind starts proving one of the caller's existing passkeys so that it
// can be linked to the account through the core bind state.
func (s *Service) BeginBind(ctx context.Context, answerUserID, state string) (AssertionCeremony, error) {
	if answerUserID == "" {
		return AssertionCeremony{}, ErrInvalidInput
	}
	if state == "" {
		return AssertionCeremony{}, ErrStateRequired
	}
	if err := checkState(state); err != nil {
		return AssertionCeremony{}, err
	}
	w, err := s.rp()
	if err != nil {
		return AssertionCeremony{}, err
	}
	handle, recs, err := s.ownCredentials(ctx, answerUserID)
	if err != nil {
		return AssertionCeremony{}, err
	}
	if len(recs) == 0 {
		return AssertionCeremony{}, ErrCredentialNotFound
	}
	user, err := bindUser(handle, recs)
	if err != nil {
		return AssertionCeremony{}, err
	}
	assertion, data, err := w.BeginLogin(user, webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		return AssertionCeremony{}, fmt.Errorf("passkey: begin bind: %w", err)
	}
	sealed, err := s.seal(ctx, s.newState(purposeBind, answerUserID, handle, state, data))
	if err != nil {
		return AssertionCeremony{}, err
	}
	return AssertionCeremony{Session: sealed, Options: assertion.Response}, nil
}

// FinishBind verifies the assertion against the caller's own passkeys and
// returns the receiver URL with a token bound to the sealed state.
func (s *Service) FinishBind(ctx context.Context, answerUserID, session string, response []byte) (string, error) {
	st, err := s.open(ctx, session, purposeBind)
	if err != nil {
		return "", err
	}
	if answerUserID == "" || st.UserID != answerUserID || st.State == "" {
		return "", ErrSessionInvalid
	}
	handle, err := s.store.UserHandle(ctx, answerUserID)
	if errors.Is(err, store.ErrNotFound) {
		return "", ErrSessionInvalid
	}
	if err != nil {
		return "", fmt.Errorf("passkey: user handle: %w", err)
	}
	if handle != st.Handle {
		return "", ErrSessionInvalid
	}
	if err := s.checkNotConsumed(ctx, st.Data.Challenge); err != nil {
		return "", err
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(response)
	if err != nil {
		return "", fmt.Errorf("%w: credential", ErrInvalidInput)
	}
	w, err := s.rp()
	if err != nil {
		return "", err
	}
	recs, err := s.credentialsOf(ctx, handle)
	if err != nil {
		return "", err
	}
	user, err := bindUser(handle, recs)
	if err != nil {
		return "", err
	}
	cred, err := w.ValidateLogin(user, st.Data, parsed)
	if err != nil {
		return "", verificationFailed("bind", err)
	}
	for _, rec := range recs {
		if bytes.Equal(rec.Credential.ID, cred.ID) {
			return s.completeAssertion(ctx, st, rec, cred)
		}
	}
	return "", ErrVerificationFailed
}

// ownCredentials returns the caller's handle and passkeys; a user without a
// handle has no passkeys (ErrCredentialNotFound).
func (s *Service) ownCredentials(ctx context.Context, answerUserID string) (string, []store.CredentialRecord, error) {
	handle, err := s.store.UserHandle(ctx, answerUserID)
	if errors.Is(err, store.ErrNotFound) {
		return "", nil, ErrCredentialNotFound
	}
	if err != nil {
		return "", nil, fmt.Errorf("passkey: user handle: %w", err)
	}
	recs, err := s.credentialsOf(ctx, handle)
	if err != nil {
		return "", nil, err
	}
	return handle, recs, nil
}

func bindUser(handle string, recs []store.CredentialRecord) (*webauthnUser, error) {
	id, err := decodeHandle(handle)
	if err != nil {
		return nil, err
	}
	creds := make([]webauthn.Credential, 0, len(recs))
	for _, rec := range recs {
		creds = append(creds, rec.Credential)
	}
	return &webauthnUser{id: id, creds: creds}, nil
}
