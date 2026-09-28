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

package store_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/apache/answer-plugins/connector-passkey/internal/store"
	"github.com/apache/answer-plugins/connector-passkey/internal/store/storetest"
	"github.com/apache/answer/plugin"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

const slug = "passkey_connector"

// kvFixture is a Store plus raw access to its backing rows.
type kvFixture struct {
	store.Store
	deleteRow func(group, key string)
	// rows returns every (group, key) pair stored, or nil when the backend
	// has no table to inspect.
	rows func() [][2]string
}

func newKVFixture(t *testing.T) kvFixture {
	t.Helper()
	op, engine := storetest.NewSQLiteKV(t, slug)
	return kvFixture{
		Store: store.NewKV(op),
		deleteRow: func(group, key string) {
			if err := op.Del(context.Background(), plugin.KVParams{Group: group, Key: key}); err != nil {
				t.Fatal(err)
			}
		},
		rows: func() [][2]string {
			res, err := engine.QueryString(`SELECT "group", "key" FROM plugin_kv_storage`)
			if err != nil {
				t.Fatal(err)
			}
			out := make([][2]string, 0, len(res))
			for _, r := range res {
				out = append(out, [2]string{r["group"], r["key"]})
			}
			return out
		},
	}
}

func newMemoryFixture(t *testing.T) kvFixture {
	s := storetest.NewMemory()
	deleter, ok := s.(interface{ DeleteRow(group, key string) })
	if !ok {
		t.Fatal("storetest memory store has no DeleteRow")
	}
	return kvFixture{Store: s, deleteRow: deleter.DeleteRow, rows: func() [][2]string { return nil }}
}

var backends = []struct {
	name string
	new  func(t *testing.T) kvFixture
}{
	{"kv", newKVFixture},
	{"memory", newMemoryFixture},
}

var t0 = time.Date(2026, 9, 27, 8, 0, 0, 0, time.UTC)

func record(handle string, id []byte, created time.Time) store.CredentialRecord {
	return store.CredentialRecord{
		UserHandle: handle,
		Name:       "key " + string(id[:1]),
		CreatedAt:  created,
		Credential: webauthn.Credential{
			ID:                id,
			PublicKey:         []byte{1, 2, 3},
			AttestationType:   "none",
			AttestationFormat: "none",
			Transport:         []protocol.AuthenticatorTransport{protocol.Internal, protocol.Hybrid},
			Flags:             webauthn.CredentialFlags{UserPresent: true, UserVerified: true, BackupEligible: true, BackupState: true},
			Authenticator:     webauthn.Authenticator{AAGUID: make([]byte, 16), SignCount: 7},
		},
	}
}

func save(t *testing.T, s store.Store, rec store.CredentialRecord, challenge string, isNew bool) {
	t.Helper()
	err := s.SaveCeremonyResult(context.Background(), store.CeremonyResult{
		Challenge: challenge, ChallengeExpiresAt: t0.Add(5 * time.Minute),
		Credential: rec, NewCredential: isNew,
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestStore(t *testing.T) {
	for _, b := range backends {
		t.Run(b.name, func(t *testing.T) {
			t.Run("EnsureUserHandle is idempotent", func(t *testing.T) {
				s, ctx := b.new(t), context.Background()
				if _, err := s.UserHandle(ctx, "u1"); !errors.Is(err, store.ErrNotFound) {
					t.Fatalf("UserHandle before ensure = %v, want ErrNotFound", err)
				}
				calls := 0
				gen := func() (string, error) { calls++; return "handle-" + string(rune('0'+calls)), nil }
				h1, err := s.EnsureUserHandle(ctx, "u1", gen)
				if err != nil {
					t.Fatal(err)
				}
				h2, err := s.EnsureUserHandle(ctx, "u1", gen)
				if err != nil {
					t.Fatal(err)
				}
				got, err := s.UserHandle(ctx, "u1")
				if err != nil || h1 != h2 || got != h1 || calls != 1 {
					t.Fatalf("handles %q %q %q (err %v), generate calls %d", h1, h2, got, err, calls)
				}
			})

			t.Run("CeremonyKey is stable", func(t *testing.T) {
				s, ctx := b.new(t), context.Background()
				k1, err := s.CeremonyKey(ctx)
				if err != nil {
					t.Fatal(err)
				}
				k2, err := s.CeremonyKey(ctx)
				if err != nil {
					t.Fatal(err)
				}
				if len(k1) != 32 || !bytes.Equal(k1, k2) {
					t.Fatalf("keys differ or have wrong length: %x %x", k1, k2)
				}
			})

			t.Run("SaveCeremonyResult writes every row", func(t *testing.T) {
				s, ctx := b.new(t), context.Background()
				rec := record("h1", []byte("cred-a"), t0)
				tok := &store.LoginToken{ExternalID: "h1", State: "st", ExpiresAt: t0.Add(2 * time.Minute)}
				err := s.SaveCeremonyResult(ctx, store.CeremonyResult{
					Challenge: "chal-1", ChallengeExpiresAt: t0.Add(5 * time.Minute),
					Credential: rec, NewCredential: true, TokenHash: "hash-1", Token: tok,
				})
				if err != nil {
					t.Fatal(err)
				}
				if used, err := s.ChallengeConsumed(ctx, "chal-1"); err != nil || !used {
					t.Fatalf("ChallengeConsumed = %v, %v", used, err)
				}
				if used, err := s.ChallengeConsumed(ctx, "chal-2"); err != nil || used {
					t.Fatalf("ChallengeConsumed(unknown) = %v, %v", used, err)
				}
				got, err := s.Credential(ctx, []byte("cred-a"))
				if err != nil {
					t.Fatal(err)
				}
				c := got.Credential
				if got.UserHandle != "h1" || got.Name != rec.Name || !got.CreatedAt.Equal(t0) || !got.LastUsedAt.IsZero() ||
					c.Authenticator.SignCount != 7 || !c.Flags.BackupEligible || !c.Flags.BackupState ||
					len(c.Transport) != 2 || c.AttestationFormat != "none" || !bytes.Equal(c.PublicKey, []byte{1, 2, 3}) {
					t.Fatalf("record did not round-trip: %+v", got)
				}
				gotTok, err := s.TakeLoginToken(ctx, "hash-1")
				if err != nil || gotTok.ExternalID != "h1" || gotTok.State != "st" || !gotTok.ExpiresAt.Equal(tok.ExpiresAt) {
					t.Fatalf("TakeLoginToken = %+v, %v", gotTok, err)
				}
			})

			t.Run("update without NewCredential keeps membership", func(t *testing.T) {
				s, ctx := b.new(t), context.Background()
				rec := record("h1", []byte("cred-a"), t0)
				save(t, s, rec, "c1", true)
				rec.LastUsedAt = t0.Add(time.Minute)
				rec.Credential.Authenticator.SignCount = 9
				save(t, s, rec, "c2", false)
				got, err := s.Credential(ctx, []byte("cred-a"))
				if err != nil || got.Credential.Authenticator.SignCount != 9 || !got.LastUsedAt.Equal(rec.LastUsedAt) {
					t.Fatalf("Credential = %+v, %v", got, err)
				}
			})

			t.Run("Credentials lists only the owner, oldest first", func(t *testing.T) {
				s, ctx := b.new(t), context.Background()
				save(t, s, record("h1", []byte("b-newer"), t0.Add(time.Hour)), "c1", true)
				save(t, s, record("h1", []byte("a-older"), t0), "c2", true)
				save(t, s, record("h2", []byte("other"), t0), "c3", true)
				recs, err := s.Credentials(ctx, "h1")
				if err != nil {
					t.Fatal(err)
				}
				if len(recs) != 2 || string(recs[0].Credential.ID) != "a-older" || string(recs[1].Credential.ID) != "b-newer" {
					t.Fatalf("Credentials(h1) = %+v", recs)
				}
				none, err := s.Credentials(ctx, "nobody")
				if err != nil || len(none) != 0 {
					t.Fatalf("Credentials(nobody) = %v, %v", none, err)
				}
			})

			t.Run("orphans read as not found", func(t *testing.T) {
				s, ctx := b.new(t), context.Background()
				id := []byte("cred-a")
				save(t, s, record("h1", id, t0), "c1", true)
				s.deleteRow(store.MembershipGroup("h1"), store.CredentialKey(id))
				if _, err := s.Credential(ctx, id); !errors.Is(err, store.ErrNotFound) {
					t.Fatalf("Credential(orphan record) = %v, want ErrNotFound", err)
				}
				id2 := []byte("cred-b")
				save(t, s, record("h1", id2, t0), "c2", true)
				s.deleteRow(store.GroupCredential, store.CredentialKey(id2))
				if _, err := s.Credential(ctx, id2); !errors.Is(err, store.ErrNotFound) {
					t.Fatalf("Credential(orphan membership) = %v, want ErrNotFound", err)
				}
				if recs, err := s.Credentials(ctx, "h1"); err != nil || len(recs) != 0 {
					t.Fatalf("Credentials with orphans = %+v, %v", recs, err)
				}
			})

			t.Run("RenameCredential overwrites the record", func(t *testing.T) {
				s, ctx := b.new(t), context.Background()
				rec := record("h1", []byte("cred-a"), t0)
				save(t, s, rec, "c1", true)
				rec.Name = "Laptop"
				if err := s.RenameCredential(ctx, rec); err != nil {
					t.Fatal(err)
				}
				if got, err := s.Credential(ctx, rec.Credential.ID); err != nil || got.Name != "Laptop" {
					t.Fatalf("Credential after rename = %+v, %v", got, err)
				}
			})

			t.Run("DeleteCredential removes both rows", func(t *testing.T) {
				s, ctx := b.new(t), context.Background()
				id := []byte("cred-a")
				save(t, s, record("h1", id, t0), "c1", true)
				save(t, s, record("h1", []byte("cred-b"), t0), "c2", true)
				if err := s.DeleteCredential(ctx, "h1", id); err != nil {
					t.Fatal(err)
				}
				if _, err := s.Credential(ctx, id); !errors.Is(err, store.ErrNotFound) {
					t.Fatalf("Credential after delete = %v", err)
				}
				recs, err := s.Credentials(ctx, "h1")
				if err != nil || len(recs) != 1 {
					t.Fatalf("Credentials after delete = %+v, %v", recs, err)
				}
				for _, row := range s.rows() {
					if row[1] == store.CredentialKey(id) {
						t.Fatalf("row %v survived the delete", row)
					}
				}
			})

			t.Run("TakeLoginToken is single use", func(t *testing.T) {
				s, ctx := b.new(t), context.Background()
				err := s.SaveCeremonyResult(ctx, store.CeremonyResult{
					Challenge: "c1", ChallengeExpiresAt: t0, Credential: record("h1", []byte("x"), t0),
					NewCredential: true, TokenHash: "th", Token: &store.LoginToken{ExternalID: "h1", State: "s", ExpiresAt: t0},
				})
				if err != nil {
					t.Fatal(err)
				}
				if _, err := s.TakeLoginToken(ctx, "th"); err != nil {
					t.Fatal(err)
				}
				if _, err := s.TakeLoginToken(ctx, "th"); !errors.Is(err, store.ErrNotFound) {
					t.Fatalf("second TakeLoginToken = %v, want ErrNotFound", err)
				}
			})

			t.Run("PurgeExpired removes only expired rows", func(t *testing.T) {
				s, ctx := b.new(t), context.Background()
				now := t0.Add(10 * time.Minute)
				for i, c := range []struct {
					challenge, hash string
					exp             time.Time
				}{
					{"old-chal", "old-tok", now.Add(-time.Second)},
					{"new-chal", "new-tok", now.Add(time.Minute)},
				} {
					err := s.SaveCeremonyResult(ctx, store.CeremonyResult{
						Challenge: c.challenge, ChallengeExpiresAt: c.exp,
						Credential: record("h1", []byte{byte('a' + i)}, t0), NewCredential: true,
						TokenHash: c.hash, Token: &store.LoginToken{ExternalID: "h1", State: "s", ExpiresAt: c.exp},
					})
					if err != nil {
						t.Fatal(err)
					}
				}
				if err := s.PurgeExpired(ctx, now); err != nil {
					t.Fatal(err)
				}
				if used, _ := s.ChallengeConsumed(ctx, "old-chal"); used {
					t.Error("expired challenge survived")
				}
				if used, _ := s.ChallengeConsumed(ctx, "new-chal"); !used {
					t.Error("live challenge was purged")
				}
				if _, err := s.TakeLoginToken(ctx, "old-tok"); !errors.Is(err, store.ErrNotFound) {
					t.Errorf("expired token survived: %v", err)
				}
				if _, err := s.TakeLoginToken(ctx, "new-tok"); err != nil {
					t.Errorf("live token was purged: %v", err)
				}
				if recs, _ := s.Credentials(ctx, "h1"); len(recs) != 2 {
					t.Errorf("purge touched credentials: %d left", len(recs))
				}
			})
		})
	}
}

// TestKVKeyLengths stores worst-case inputs (1023-byte credential ID, 64-char
// Answer user ID, 43-char handle, token hash and challenge) and checks every
// group and key fits the VARCHAR(128) columns.
func TestKVKeyLengths(t *testing.T) {
	s, ctx := newKVFixture(t), context.Background()
	userID := strings.Repeat("9", 64)
	handle := strings.Repeat("h", 43)
	if _, err := s.EnsureUserHandle(ctx, userID, func() (string, error) { return handle, nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CeremonyKey(ctx); err != nil {
		t.Fatal(err)
	}
	longID := bytes.Repeat([]byte{0xff}, 1023)
	err := s.SaveCeremonyResult(ctx, store.CeremonyResult{
		Challenge: strings.Repeat("c", 43), ChallengeExpiresAt: t0,
		Credential: record(handle, longID, t0), NewCredential: true,
		TokenHash: strings.Repeat("t", 43), Token: &store.LoginToken{ExternalID: handle, State: "s", ExpiresAt: t0},
	})
	if err != nil {
		t.Fatal(err)
	}
	rows := s.rows()
	if len(rows) != 6 {
		t.Fatalf("expected 6 rows, got %d: %v", len(rows), rows)
	}
	for _, row := range rows {
		if len(row[0]) > 128 || len(row[1]) > 128 {
			t.Errorf("group/key too long: %q (%d) / %q (%d)", row[0], len(row[0]), row[1], len(row[1]))
		}
	}
	if _, err := s.Credential(ctx, longID); err != nil {
		t.Fatalf("Credential(long id) = %v", err)
	}
}

// TestPurgeExpiredPages checks that one purge removes more expired rows than
// fit in one page.
func TestPurgeExpiredPages(t *testing.T) {
	for _, b := range backends {
		t.Run(b.name, func(t *testing.T) {
			s, ctx := b.new(t), context.Background()
			now := t0.Add(10 * time.Minute)
			const expired = 250
			for i := range expired + 3 {
				exp := now.Add(-time.Second)
				if i >= expired {
					exp = now.Add(time.Minute)
				}
				err := s.SaveCeremonyResult(ctx, store.CeremonyResult{
					Challenge: fmt.Sprintf("chal-%03d", i), ChallengeExpiresAt: exp,
					Credential: record("h1", []byte("x"), t0), NewCredential: i == 0,
				})
				if err != nil {
					t.Fatal(err)
				}
			}
			if err := s.PurgeExpired(ctx, now); err != nil {
				t.Fatal(err)
			}
			for i := range expired + 3 {
				used, err := s.ChallengeConsumed(ctx, fmt.Sprintf("chal-%03d", i))
				if err != nil || used != (i >= expired) {
					t.Fatalf("challenge %d consumed = %v, %v after purge", i, used, err)
				}
			}
		})
	}
}
