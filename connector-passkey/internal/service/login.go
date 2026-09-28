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
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/apache/answer-plugins/connector-passkey/internal/store"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/segmentfault/pacman/log"
)

// BeginLogin starts a discoverable (usernameless) sign-in for the core login
// state, which must come with the proof from LoginStateProof. It performs no
// store write apart from reading the ceremony key.
func (s *Service) BeginLogin(ctx context.Context, state, proof string) (AssertionCeremony, error) {
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
	if err := s.checkLoginStateProof(ctx, state, proof); err != nil {
		return AssertionCeremony{}, err
	}
	assertion, data, err := w.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		return AssertionCeremony{}, fmt.Errorf("passkey: begin login: %w", err)
	}
	sealed, err := s.seal(ctx, s.newState(purposeLogin, "", "", state, data))
	if err != nil {
		return AssertionCeremony{}, err
	}
	return AssertionCeremony{Session: sealed, Options: assertion.Response}, nil
}

// FinishLogin verifies a discoverable assertion and returns the core
// receiver URL carrying a one-time token bound to the sealed state.
func (s *Service) FinishLogin(ctx context.Context, session string, response []byte) (string, error) {
	st, err := s.open(ctx, session, purposeLogin)
	if err != nil {
		return "", err
	}
	if st.State == "" {
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

	var (
		rec      store.CredentialRecord
		storeErr error
	)
	handler := func(rawID, userHandle []byte) (webauthn.User, error) {
		found, err := s.store.Credential(ctx, rawID)
		if err != nil {
			if !errors.Is(err, store.ErrNotFound) {
				storeErr = err
			}
			return nil, err
		}
		// The owner comes from the stored record; the asserted user handle
		// must match it.
		if found.UserHandle != base64.RawURLEncoding.EncodeToString(userHandle) {
			return nil, errors.New("user handle does not own the credential")
		}
		rec = found
		return &webauthnUser{id: userHandle, creds: []webauthn.Credential{found.Credential}}, nil
	}
	_, cred, err := w.ValidatePasskeyLogin(handler, st.Data, parsed)
	if storeErr != nil {
		return "", fmt.Errorf("passkey: credential lookup: %w", storeErr)
	}
	if err != nil {
		return "", verificationFailed("login", err)
	}
	return s.completeAssertion(ctx, st, rec, cred)
}

// completeAssertion applies the clone check, persists the updated credential
// together with the consumed challenge and a login token, and returns the
// receiver URL.
//
// Under the challenge lock it re-checks that the challenge is unused, and
// under the credential lock it re-reads the stored record right before the
// transaction: a passkey deleted meanwhile is not written back, and a name
// or sign counter written meanwhile is not rolled back. rec is the record the
// assertion was verified against.
func (s *Service) completeAssertion(ctx context.Context, st ceremonyState, rec store.CredentialRecord, cred *webauthn.Credential) (string, error) {
	token, err := s.saveAssertion(ctx, st, rec, cred)
	if err != nil {
		return "", err
	}
	s.purge(ctx)
	return s.receiverURL(token, st.State), nil
}

// saveAssertion is the locked part of completeAssertion. It returns the raw
// login token.
func (s *Service) saveAssertion(ctx context.Context, st ceremonyState, rec store.CredentialRecord, cred *webauthn.Credential) (string, error) {
	unlockChallenge := s.challengeLocks.lock(st.Data.Challenge)
	defer unlockChallenge()
	// A replayed session is reported as such, before the counter check that
	// its already-saved counter would trip.
	if err := s.checkNotConsumed(ctx, st.Data.Challenge); err != nil {
		return "", err
	}
	if cred.Authenticator.CloneWarning {
		return "", cloneDetected(cred.ID)
	}
	unlockCredential := s.credentialLocks.lock(store.CredentialKey(cred.ID))
	defer unlockCredential()
	fresh, err := s.store.Credential(ctx, cred.ID)
	if errors.Is(err, store.ErrNotFound) {
		log.Debugf("passkey: credential %s was deleted during the ceremony", store.CredentialKey(cred.ID))
		return "", ErrVerificationFailed
	}
	if err != nil {
		return "", fmt.Errorf("passkey: credential lookup: %w", err)
	}
	if fresh.UserHandle != rec.UserHandle {
		return "", ErrVerificationFailed
	}
	// The library compared the counter with rec; compare it with the record
	// as stored now in case another sign-in raised it meanwhile.
	if old, got := fresh.Credential.Authenticator.SignCount, cred.Authenticator.SignCount; (old != 0 || got != 0) && got <= old {
		return "", cloneDetected(cred.ID)
	}
	fresh.Credential = *cred
	fresh.LastUsedAt = s.nowUTC()

	token, hash, tok, err := s.newLoginToken(fresh.UserHandle, st.State)
	if err != nil {
		return "", err
	}
	err = s.store.SaveCeremonyResult(ctx, store.CeremonyResult{
		Challenge:          st.Data.Challenge,
		ChallengeExpiresAt: s.consumedUntil(st),
		Credential:         fresh,
		TokenHash:          hash,
		Token:              tok,
	})
	if err != nil {
		return "", s.saveFailed(ctx, st.Data.Challenge, "save assertion", err)
	}
	return token, nil
}

func cloneDetected(id []byte) error {
	log.Warnf("passkey: sign counter regression for credential %s; sign-in rejected", store.CredentialKey(id))
	return ErrCloneDetected
}
