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
	"errors"
	"fmt"

	"github.com/apache/answer-plugins/connector-passkey/internal/store"
)

// Credentials lists the caller's passkeys, oldest first. It never creates a
// user handle.
func (s *Service) Credentials(ctx context.Context, answerUserID string) ([]Credential, error) {
	handle, err := s.store.UserHandle(ctx, answerUserID)
	if errors.Is(err, store.ErrNotFound) {
		return []Credential{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("passkey: user handle: %w", err)
	}
	recs, err := s.credentialsOf(ctx, handle)
	if err != nil {
		return nil, err
	}
	views := make([]Credential, 0, len(recs))
	for _, rec := range recs {
		views = append(views, toView(rec))
	}
	return views, nil
}

// RenameCredential sets the nickname of one of the caller's passkeys. The
// record is read and written under the credential lock, so the write keeps
// the sign counter and last use saved by a concurrent sign-in in this
// process; only the name changes.
func (s *Service) RenameCredential(ctx context.Context, answerUserID string, id []byte, name string) (Credential, error) {
	name, err := sanitizeLabel(name, true)
	if err != nil {
		return Credential{}, ErrInvalidName
	}
	unlock := s.credentialLocks.lock(store.CredentialKey(id))
	defer unlock()
	_, rec, err := s.ownedCredential(ctx, answerUserID, id)
	if err != nil {
		return Credential{}, err
	}
	if rec.Name == name {
		return toView(rec), nil // an identical write would fail on MySQL
	}
	rec.Name = name
	if err := s.store.RenameCredential(ctx, rec); err != nil {
		// Deleted meanwhile (for example by another instance): not found.
		if _, _, rerr := s.ownedCredential(ctx, answerUserID, id); errors.Is(rerr, ErrCredentialNotFound) {
			return Credential{}, ErrCredentialNotFound
		}
		return Credential{}, fmt.Errorf("passkey: rename credential: %w", err)
	}
	return toView(rec), nil
}

// DeleteCredential removes one of the caller's passkeys.
func (s *Service) DeleteCredential(ctx context.Context, answerUserID string, id []byte) error {
	unlock := s.credentialLocks.lock(store.CredentialKey(id))
	defer unlock()
	handle, _, err := s.ownedCredential(ctx, answerUserID, id)
	if err != nil {
		return err
	}
	if err := s.store.DeleteCredential(ctx, handle, id); err != nil {
		return fmt.Errorf("passkey: delete credential: %w", err)
	}
	return nil
}

// ownedCredential returns the record of id if it belongs to the caller, and
// ErrCredentialNotFound otherwise (also for another user's passkey).
func (s *Service) ownedCredential(ctx context.Context, answerUserID string, id []byte) (string, store.CredentialRecord, error) {
	if len(id) == 0 {
		return "", store.CredentialRecord{}, ErrCredentialNotFound
	}
	handle, err := s.store.UserHandle(ctx, answerUserID)
	if errors.Is(err, store.ErrNotFound) {
		return "", store.CredentialRecord{}, ErrCredentialNotFound
	}
	if err != nil {
		return "", store.CredentialRecord{}, fmt.Errorf("passkey: user handle: %w", err)
	}
	rec, err := s.store.Credential(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return "", store.CredentialRecord{}, ErrCredentialNotFound
	}
	if err != nil {
		return "", store.CredentialRecord{}, fmt.Errorf("passkey: credential lookup: %w", err)
	}
	if rec.UserHandle != handle {
		return "", store.CredentialRecord{}, ErrCredentialNotFound
	}
	return handle, rec, nil
}
