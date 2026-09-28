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

// Package store persists passkey data. Store is the only persistence contract
// the service layer depends on; NewKV implements it on the Answer plugin KV
// storage and storetest.NewMemory provides an in-memory fake for tests.
package store

import (
	"context"
	"errors"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

// ErrNotFound is returned when a record does not exist. A credential whose
// record row or membership row is missing (an orphan) is also not found.
var ErrNotFound = errors.New("passkey store: not found")

// CredentialRecord is one registered passkey. The owner is the WebAuthn user
// handle; the full webauthn.Credential is kept so that the sign counter,
// flags, transports and attestation data round-trip.
type CredentialRecord struct {
	UserHandle string              `json:"user_handle"`
	Name       string              `json:"name"`
	CreatedAt  time.Time           `json:"created_at"`
	LastUsedAt time.Time           `json:"last_used_at,omitzero"`
	Credential webauthn.Credential `json:"credential"`
}

// LoginToken is the one-time token handed to the Answer connector receiver.
// It is stored under the SHA-256 hash of the raw token.
type LoginToken struct {
	ExternalID string    `json:"external_id"`
	State      string    `json:"state"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// CeremonyResult is everything a successful finish-* call persists in one
// transaction.
type CeremonyResult struct {
	// Challenge is marked consumed until ChallengeExpiresAt.
	Challenge          string
	ChallengeExpiresAt time.Time
	// Credential is written as a whole (new or updated record).
	Credential CredentialRecord
	// NewCredential also adds the membership row of Credential.UserHandle.
	NewCredential bool
	// Token, when non-nil, is stored under TokenHash.
	TokenHash string
	Token     *LoginToken
}

// Store is the persistence contract of the passkey service.
type Store interface {
	// CeremonyKey returns the shared 32-byte AES key for ceremony sessions,
	// creating it on first use.
	CeremonyKey(ctx context.Context) ([]byte, error)
	// UserHandle returns the handle of an Answer user or ErrNotFound.
	UserHandle(ctx context.Context, answerUserID string) (string, error)
	// EnsureUserHandle returns the handle of an Answer user, creating it with
	// generate when there is none.
	EnsureUserHandle(ctx context.Context, answerUserID string, generate func() (string, error)) (string, error)
	// Credential returns the record of a credential ID or ErrNotFound.
	Credential(ctx context.Context, credentialID []byte) (CredentialRecord, error)
	// Credentials lists the records of a user handle sorted by CreatedAt.
	Credentials(ctx context.Context, userHandle string) ([]CredentialRecord, error)
	// RenameCredential overwrites an existing record (single write).
	RenameCredential(ctx context.Context, rec CredentialRecord) error
	// DeleteCredential removes a record and its membership row.
	DeleteCredential(ctx context.Context, userHandle string, credentialID []byte) error
	// ChallengeConsumed reports whether a ceremony challenge was already used.
	ChallengeConsumed(ctx context.Context, challenge string) (bool, error)
	// SaveCeremonyResult persists a finished ceremony atomically.
	SaveCeremonyResult(ctx context.Context, r CeremonyResult) error
	// TakeLoginToken returns and deletes a login token or returns ErrNotFound.
	// The caller checks expiry and state.
	TakeLoginToken(ctx context.Context, tokenHash string) (LoginToken, error)
	// PurgeExpired removes expired consumed challenges and login tokens.
	PurgeExpired(ctx context.Context, now time.Time) error
}
