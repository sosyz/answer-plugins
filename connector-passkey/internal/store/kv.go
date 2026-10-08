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

package store

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"time"

	"github.com/apache/answer/plugin"
	"github.com/segmentfault/pacman/log"
)

// kvStore implements Store on the Answer plugin KV storage.
//
// Rules, dictated by plugin.KVOperator:
//   - The operator must have its cache disabled (WithCacheTTL(-1)); the plugin
//     adapter does that before calling NewKV.
//   - No Get inside Tx: the transaction operator has cacheTTL 0 and Tx wraps
//     inner errors with %v, so errors.Is does not survive. Every existence,
//     owner, limit or consumed check happens before the transaction and the
//     transaction only issues Set and Del.
//   - Never Set a value equal to the stored one: on MySQL a no-op UPDATE
//     reports 0 affected rows and Set then fails with a duplicate INSERT.
type kvStore struct {
	op *plugin.KVOperator
}

var _ Store = (*kvStore)(nil)

// NewKV returns a Store backed by op.
func NewKV(op *plugin.KVOperator) Store {
	return &kvStore{op: op}
}

func (s *kvStore) get(ctx context.Context, group, key string) (string, error) {
	v, err := s.op.Get(ctx, plugin.KVParams{Group: group, Key: key})
	if errors.Is(err, plugin.ErrKVKeyNotFound) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("passkey store: get %s: %w", group, err)
	}
	return v, nil
}

func (s *kvStore) set(ctx context.Context, group, key, value string) error {
	if err := s.op.Set(ctx, plugin.KVParams{Group: group, Key: key, Value: value}); err != nil {
		return fmt.Errorf("passkey store: set %s: %w", group, err)
	}
	return nil
}

// getOrCreate returns the stored value, or generates and stores one when
// there is none. KVOperator.Set is an upsert, so two concurrent creators both
// succeed and the last writer wins; the caller whose value was overwritten
// sees its later reads fail (for example session_invalid) and retries. If Set
// fails, the value is read again in case another creator stored one.
func (s *kvStore) getOrCreate(ctx context.Context, group, key string, generate func() (string, error)) (string, error) {
	v, err := s.get(ctx, group, key)
	if err == nil {
		return v, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return "", err
	}
	v, err = generate()
	if err != nil {
		return "", err
	}
	if setErr := s.set(ctx, group, key, v); setErr != nil {
		stored, err := s.get(ctx, group, key)
		if err != nil {
			return "", setErr
		}
		return stored, nil
	}
	return v, nil
}

func (s *kvStore) CeremonyKey(ctx context.Context) ([]byte, error) {
	encoded, err := s.getOrCreate(ctx, GroupSecret, KeyCeremony, func() (string, error) {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return "", err
		}
		return base64.RawURLEncoding.EncodeToString(b), nil
	})
	if err != nil {
		return nil, err
	}
	key, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(key) != 32 {
		return nil, errors.New("passkey store: stored ceremony key is malformed")
	}
	return key, nil
}

func (s *kvStore) UserHandle(ctx context.Context, answerUserID string) (string, error) {
	return s.get(ctx, GroupUserHandle, answerUserID)
}

func (s *kvStore) EnsureUserHandle(ctx context.Context, answerUserID string, generate func() (string, error)) (string, error) {
	return s.getOrCreate(ctx, GroupUserHandle, answerUserID, generate)
}

func (s *kvStore) record(ctx context.Context, key string) (CredentialRecord, error) {
	raw, err := s.get(ctx, GroupCredential, key)
	if err != nil {
		return CredentialRecord{}, err
	}
	var rec CredentialRecord
	if err := json.Unmarshal([]byte(raw), &rec); err != nil {
		return CredentialRecord{}, fmt.Errorf("passkey store: decode credential: %w", err)
	}
	return rec, nil
}

func (s *kvStore) Credential(ctx context.Context, credentialID []byte) (CredentialRecord, error) {
	key := CredentialKey(credentialID)
	rec, err := s.record(ctx, key)
	if err != nil {
		return CredentialRecord{}, err
	}
	if !bytes.Equal(rec.Credential.ID, credentialID) {
		return CredentialRecord{}, ErrNotFound
	}
	if _, err := s.get(ctx, MembershipGroup(rec.UserHandle), key); err != nil {
		return CredentialRecord{}, err // ErrNotFound for an orphan record
	}
	return rec, nil
}

func (s *kvStore) Credentials(ctx context.Context, userHandle string) ([]CredentialRecord, error) {
	members, err := s.op.GetByGroup(ctx, plugin.KVParams{Group: MembershipGroup(userHandle), Page: 1, PageSize: groupPageSize})
	if err != nil {
		return nil, fmt.Errorf("passkey store: list credentials: %w", err)
	}
	recs := make([]CredentialRecord, 0, len(members))
	for key := range members {
		rec, err := s.record(ctx, key)
		if errors.Is(err, ErrNotFound) {
			log.Warnf("passkey: membership row %s has no credential record; skipped", key)
			continue
		}
		if err != nil {
			return nil, err
		}
		if rec.UserHandle != userHandle {
			log.Warnf("passkey: credential %s is owned by another user handle; skipped", key)
			continue
		}
		recs = append(recs, rec)
	}
	sortRecords(recs)
	return recs, nil
}

func (s *kvStore) RenameCredential(ctx context.Context, rec CredentialRecord) error {
	raw, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("passkey store: encode credential: %w", err)
	}
	return s.set(ctx, GroupCredential, CredentialKey(rec.Credential.ID), string(raw))
}

func (s *kvStore) DeleteCredential(ctx context.Context, userHandle string, credentialID []byte) error {
	key := CredentialKey(credentialID)
	err := s.op.Tx(ctx, func(ctx context.Context, tx *plugin.KVOperator) error {
		if err := tx.Del(ctx, plugin.KVParams{Group: GroupCredential, Key: key}); err != nil {
			return err
		}
		return tx.Del(ctx, plugin.KVParams{Group: MembershipGroup(userHandle), Key: key})
	})
	if err != nil {
		return fmt.Errorf("passkey store: delete credential: %w", err)
	}
	return nil
}

func (s *kvStore) ChallengeConsumed(ctx context.Context, challenge string) (bool, error) {
	_, err := s.get(ctx, GroupConsumedChallenge, challenge)
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func (s *kvStore) SaveCeremonyResult(ctx context.Context, r CeremonyResult) error {
	if r.Challenge == "" {
		return errors.New("passkey store: ceremony result without challenge")
	}
	recRaw, err := json.Marshal(r.Credential)
	if err != nil {
		return fmt.Errorf("passkey store: encode credential: %w", err)
	}
	var tokenRaw []byte
	if r.Token != nil {
		if r.TokenHash == "" {
			return errors.New("passkey store: login token without hash")
		}
		if tokenRaw, err = json.Marshal(r.Token); err != nil {
			return fmt.Errorf("passkey store: encode login token: %w", err)
		}
	}
	credKey := CredentialKey(r.Credential.Credential.ID)
	expiry := strconv.FormatInt(r.ChallengeExpiresAt.Unix(), 10)

	err = s.op.Tx(ctx, func(ctx context.Context, tx *plugin.KVOperator) error {
		if err := tx.Set(ctx, plugin.KVParams{Group: GroupConsumedChallenge, Key: r.Challenge, Value: expiry}); err != nil {
			return err
		}
		if err := tx.Set(ctx, plugin.KVParams{Group: GroupCredential, Key: credKey, Value: string(recRaw)}); err != nil {
			return err
		}
		if r.NewCredential {
			if err := tx.Set(ctx, plugin.KVParams{Group: MembershipGroup(r.Credential.UserHandle), Key: credKey, Value: membershipValue}); err != nil {
				return err
			}
		}
		if r.Token != nil {
			if err := tx.Set(ctx, plugin.KVParams{Group: GroupLoginToken, Key: r.TokenHash, Value: string(tokenRaw)}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("passkey store: save ceremony result: %w", err)
	}
	return nil
}

func (s *kvStore) TakeLoginToken(ctx context.Context, tokenHash string) (LoginToken, error) {
	raw, err := s.get(ctx, GroupLoginToken, tokenHash)
	if err != nil {
		return LoginToken{}, err
	}
	if err := s.op.Del(ctx, plugin.KVParams{Group: GroupLoginToken, Key: tokenHash}); err != nil {
		return LoginToken{}, fmt.Errorf("passkey store: delete login token: %w", err)
	}
	var tok LoginToken
	if err := json.Unmarshal([]byte(raw), &tok); err != nil {
		return LoginToken{}, fmt.Errorf("passkey store: decode login token: %w", err)
	}
	return tok, nil
}

func (s *kvStore) PurgeExpired(ctx context.Context, now time.Time) error {
	var errs []error
	errs = append(errs, s.purgeGroup(ctx, GroupConsumedChallenge, now, challengeExpired))
	errs = append(errs, s.purgeGroup(ctx, GroupLoginToken, now, tokenExpired))
	return errors.Join(errs...)
}

// purgeGroup deletes expired rows of group, oldest first, one page at a
// time. It stops at a page that is not full or not entirely expired (rows
// are roughly in expiry order), and after maxPurgePages pages so that one
// call stays bounded; the next purge continues.
func (s *kvStore) purgeGroup(ctx context.Context, group string, now time.Time, expired func(value string, now time.Time) bool) error {
	for range maxPurgePages {
		rows, err := s.op.GetByGroup(ctx, plugin.KVParams{Group: group, Page: 1, PageSize: groupPageSize})
		if err != nil {
			return fmt.Errorf("passkey store: purge %s: %w", group, err)
		}
		var errs []error
		deleted := 0
		for key, value := range rows {
			if !expired(value, now) {
				continue
			}
			if err := s.op.Del(ctx, plugin.KVParams{Group: group, Key: key}); err != nil {
				errs = append(errs, fmt.Errorf("passkey store: purge %s: %w", group, err))
				continue
			}
			deleted++
		}
		if len(errs) > 0 {
			return errors.Join(errs...)
		}
		if len(rows) < groupPageSize || deleted < len(rows) {
			return nil
		}
	}
	return nil
}

// challengeExpired treats unparsable rows as expired so they get removed.
func challengeExpired(value string, now time.Time) bool {
	unix, err := strconv.ParseInt(value, 10, 64)
	return err != nil || time.Unix(unix, 0).Before(now)
}

func tokenExpired(value string, now time.Time) bool {
	var tok LoginToken
	return json.Unmarshal([]byte(value), &tok) != nil || tok.ExpiresAt.Before(now)
}

func sortRecords(recs []CredentialRecord) {
	sort.SliceStable(recs, func(i, j int) bool {
		if !recs[i].CreatedAt.Equal(recs[j].CreatedAt) {
			return recs[i].CreatedAt.Before(recs[j].CreatedAt)
		}
		return CredentialKey(recs[i].Credential.ID) < CredentialKey(recs[j].Credential.ID)
	})
}
