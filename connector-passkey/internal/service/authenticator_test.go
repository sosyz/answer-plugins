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
	"sync"
	"testing"
	"time"

	"github.com/apache/answer-plugins/connector-passkey/internal/rp"
	"github.com/apache/answer-plugins/connector-passkey/internal/store"
	"github.com/apache/answer-plugins/connector-passkey/internal/store/storetest"
	"github.com/apache/answer-plugins/connector-passkey/internal/webauthntest"
	"github.com/go-webauthn/webauthn/webauthn"
)

const (
	testRPID   = "example.com"
	testOrigin = "https://example.com"
	// testReceiver is the core receiver URL for the Site URL
	// https://example.com/community/.
	testReceiver = "https://example.com/community/answer/api/v1/connector/redirect/passkey"
)

// authenticator is the software passkey used by the service tests.
type authenticator = webauthntest.Authenticator

func newAuthenticator(t *testing.T) *authenticator {
	return webauthntest.New(t, testOrigin)
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// countingStore records write calls on top of another Store.
type countingStore struct {
	store.Store
	mu     sync.Mutex
	writes map[string]int
}

func (c *countingStore) count(name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writes[name]++
}

func (c *countingStore) Writes() map[string]int {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[string]int, len(c.writes))
	for k, v := range c.writes {
		out[k] = v
	}
	return out
}

func (c *countingStore) EnsureUserHandle(ctx context.Context, id string, gen func() (string, error)) (string, error) {
	c.count("EnsureUserHandle")
	return c.Store.EnsureUserHandle(ctx, id, gen)
}

func (c *countingStore) RenameCredential(ctx context.Context, rec store.CredentialRecord) error {
	c.count("RenameCredential")
	return c.Store.RenameCredential(ctx, rec)
}

func (c *countingStore) DeleteCredential(ctx context.Context, h string, id []byte) error {
	c.count("DeleteCredential")
	return c.Store.DeleteCredential(ctx, h, id)
}

func (c *countingStore) SaveCeremonyResult(ctx context.Context, r store.CeremonyResult) error {
	c.count("SaveCeremonyResult")
	return c.Store.SaveCeremonyResult(ctx, r)
}

func (c *countingStore) TakeLoginToken(ctx context.Context, h string) (store.LoginToken, error) {
	c.count("TakeLoginToken")
	return c.Store.TakeLoginToken(ctx, h)
}

type harness struct {
	t     *testing.T
	svc   *Service
	store *countingStore
	clock *fakeClock
	ctx   context.Context
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	return newHarnessOn(t, storetest.NewMemory())
}

// newHarnessOn returns a harness whose service runs on inner (wrapped in a
// countingStore).
func newHarnessOn(t *testing.T, inner store.Store) *harness {
	t.Helper()
	settings := rp.Settings{Name: "Example", ID: testRPID, Origins: []string{testOrigin}}
	w, err := settings.WebAuthn()
	if err != nil {
		t.Fatal(err)
	}
	clock := &fakeClock{now: time.Now().UTC().Truncate(time.Second)}
	cs := &countingStore{Store: inner, writes: map[string]int{}}
	svc := New(Config{
		Store:        cs,
		RelyingParty: func() (*webauthn.WebAuthn, error) { return w, nil },
		ReceiverURL:  func() string { return testReceiver },
		CeremonyTTL:  rp.CeremonyTimeout,
		Now:          clock.Now,
	})
	return &harness{t: t, svc: svc, store: cs, clock: clock, ctx: context.Background()}
}

func label(user string) UserLabel {
	return UserLabel{Name: user + "-name", DisplayName: user + " Display"}
}

// register runs a full registration ceremony and fails the test on error.
func (h *harness) register(user string, a *authenticator, state string) (Credential, string) {
	h.t.Helper()
	cer, err := h.svc.BeginRegistration(h.ctx, user, label(user), state)
	if err != nil {
		h.t.Fatalf("BeginRegistration: %v", err)
	}
	cred, redirect, err := h.svc.FinishRegistration(h.ctx, user, cer.Session, "", a.Create(cer.Options))
	if err != nil {
		h.t.Fatalf("FinishRegistration: %v", err)
	}
	return cred, redirect
}

// proof returns the login state proof ConnectorSender would add for state.
func (h *harness) proof(state string) string {
	h.t.Helper()
	p, err := h.svc.LoginStateProof(h.ctx, state)
	if err != nil {
		h.t.Fatalf("LoginStateProof: %v", err)
	}
	return p
}

// login runs a discoverable login with a.
func (h *harness) login(a *authenticator, state string) (string, error) {
	h.t.Helper()
	cer, err := h.svc.BeginLogin(h.ctx, state, h.proof(state))
	if err != nil {
		h.t.Fatalf("BeginLogin: %v", err)
	}
	return h.svc.FinishLogin(h.ctx, cer.Session, a.Get(cer.Options))
}

func (h *harness) handle(user string) string {
	h.t.Helper()
	hd, err := h.store.UserHandle(h.ctx, user)
	if err != nil {
		h.t.Fatalf("UserHandle(%s): %v", user, err)
	}
	return hd
}

func (h *harness) record(id []byte) store.CredentialRecord {
	h.t.Helper()
	rec, err := h.store.Credential(h.ctx, id)
	if err != nil {
		h.t.Fatalf("Credential: %v", err)
	}
	return rec
}
