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

// Package storetest provides an in-memory store.Store for tests. It follows
// the same semantics as the KV implementation (ErrNotFound, orphan rules,
// ordering, single-use tokens) and is checked against it by a shared test
// suite in package store.
package storetest

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/apache/answer-plugins/connector-passkey/internal/store"
)

type memory struct {
	mu          sync.Mutex
	ceremonyKey []byte
	handles     map[string]string          // answer user id -> handle
	creds       map[string][]byte          // credential key -> JSON record
	members     map[string]map[string]bool // handle -> credential keys
	consumed    map[string]time.Time       // challenge -> expiry
	tokens      map[string][]byte          // token hash -> JSON token
}

// NewMemory returns an empty in-memory Store. Records are kept JSON-encoded,
// exactly as the KV implementation stores them, so round-trip behaviour
// matches.
func NewMemory() store.Store {
	return &memory{
		handles:  map[string]string{},
		creds:    map[string][]byte{},
		members:  map[string]map[string]bool{},
		consumed: map[string]time.Time{},
		tokens:   map[string][]byte{},
	}
}

// DeleteRow removes one raw row, mirroring a KV Del of (group, key). Tests use
// it to create orphans.
func (m *memory) DeleteRow(group, key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	switch {
	case group == store.GroupCredential:
		delete(m.creds, key)
	case strings.HasPrefix(group, store.GroupMembershipPrefix):
		delete(m.members[strings.TrimPrefix(group, store.GroupMembershipPrefix)], key)
	case group == store.GroupUserHandle:
		delete(m.handles, key)
	case group == store.GroupConsumedChallenge:
		delete(m.consumed, key)
	case group == store.GroupLoginToken:
		delete(m.tokens, key)
	}
}

func (m *memory) CeremonyKey(context.Context) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ceremonyKey == nil {
		k := make([]byte, 32)
		if _, err := rand.Read(k); err != nil {
			return nil, err
		}
		m.ceremonyKey = k
	}
	return bytes.Clone(m.ceremonyKey), nil
}

func (m *memory) UserHandle(_ context.Context, answerUserID string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	h, ok := m.handles[answerUserID]
	if !ok {
		return "", store.ErrNotFound
	}
	return h, nil
}

func (m *memory) EnsureUserHandle(_ context.Context, answerUserID string, generate func() (string, error)) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if h, ok := m.handles[answerUserID]; ok {
		return h, nil
	}
	h, err := generate()
	if err != nil {
		return "", err
	}
	m.handles[answerUserID] = h
	return h, nil
}

func (m *memory) record(key string) (store.CredentialRecord, error) {
	raw, ok := m.creds[key]
	if !ok {
		return store.CredentialRecord{}, store.ErrNotFound
	}
	var rec store.CredentialRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return store.CredentialRecord{}, err
	}
	return rec, nil
}

func (m *memory) Credential(_ context.Context, credentialID []byte) (store.CredentialRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := store.CredentialKey(credentialID)
	rec, err := m.record(key)
	if err != nil {
		return store.CredentialRecord{}, err
	}
	if !bytes.Equal(rec.Credential.ID, credentialID) || !m.members[rec.UserHandle][key] {
		return store.CredentialRecord{}, store.ErrNotFound
	}
	return rec, nil
}

func (m *memory) Credentials(_ context.Context, userHandle string) ([]store.CredentialRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	recs := []store.CredentialRecord{}
	for key := range m.members[userHandle] {
		rec, err := m.record(key)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if rec.UserHandle != userHandle {
			continue
		}
		recs = append(recs, rec)
	}
	sort.SliceStable(recs, func(i, j int) bool {
		if !recs[i].CreatedAt.Equal(recs[j].CreatedAt) {
			return recs[i].CreatedAt.Before(recs[j].CreatedAt)
		}
		return store.CredentialKey(recs[i].Credential.ID) < store.CredentialKey(recs[j].Credential.ID)
	})
	return recs, nil
}

func (m *memory) RenameCredential(_ context.Context, rec store.CredentialRecord) error {
	raw, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.creds[store.CredentialKey(rec.Credential.ID)] = raw
	return nil
}

func (m *memory) DeleteCredential(_ context.Context, userHandle string, credentialID []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := store.CredentialKey(credentialID)
	delete(m.creds, key)
	delete(m.members[userHandle], key)
	return nil
}

func (m *memory) ChallengeConsumed(_ context.Context, challenge string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.consumed[challenge]
	return ok, nil
}

func (m *memory) SaveCeremonyResult(_ context.Context, r store.CeremonyResult) error {
	if r.Challenge == "" {
		return errors.New("storetest: ceremony result without challenge")
	}
	recRaw, err := json.Marshal(r.Credential)
	if err != nil {
		return err
	}
	var tokRaw []byte
	if r.Token != nil {
		if r.TokenHash == "" {
			return errors.New("storetest: login token without hash")
		}
		if tokRaw, err = json.Marshal(r.Token); err != nil {
			return err
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	key := store.CredentialKey(r.Credential.Credential.ID)
	m.consumed[r.Challenge] = time.Unix(r.ChallengeExpiresAt.Unix(), 0)
	m.creds[key] = recRaw
	if r.NewCredential {
		if m.members[r.Credential.UserHandle] == nil {
			m.members[r.Credential.UserHandle] = map[string]bool{}
		}
		m.members[r.Credential.UserHandle][key] = true
	}
	if r.Token != nil {
		m.tokens[r.TokenHash] = tokRaw
	}
	return nil
}

func (m *memory) TakeLoginToken(_ context.Context, tokenHash string) (store.LoginToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	raw, ok := m.tokens[tokenHash]
	if !ok {
		return store.LoginToken{}, store.ErrNotFound
	}
	delete(m.tokens, tokenHash)
	var tok store.LoginToken
	if err := json.Unmarshal(raw, &tok); err != nil {
		return store.LoginToken{}, err
	}
	return tok, nil
}

func (m *memory) PurgeExpired(_ context.Context, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for c, exp := range m.consumed {
		if exp.Before(now) {
			delete(m.consumed, c)
		}
	}
	for h, raw := range m.tokens {
		var tok store.LoginToken
		if json.Unmarshal(raw, &tok) != nil || tok.ExpiresAt.Before(now) {
			delete(m.tokens, h)
		}
	}
	return nil
}
