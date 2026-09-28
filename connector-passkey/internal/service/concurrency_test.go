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
	"errors"
	"sync"
	"testing"

	"github.com/apache/answer-plugins/connector-passkey/internal/store"
	"github.com/apache/answer-plugins/connector-passkey/internal/store/storetest"
)

// concurrency is the number of simultaneous calls in the single-use tests.
const concurrency = 8

// newSQLiteHarness returns a harness on the real KV store over SQLite.
func newSQLiteHarness(t *testing.T) *harness {
	t.Helper()
	op, _ := storetest.NewSQLiteKV(t, "passkey_connector")
	return newHarnessOn(t, store.NewKV(op))
}

// race runs fn concurrency times at once and returns the errors.
func race(fn func() error) []error {
	var (
		wg    sync.WaitGroup
		start = make(chan struct{})
		errs  = make([]error, concurrency)
	)
	for i := range concurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs[i] = fn()
		}()
	}
	close(start)
	wg.Wait()
	return errs
}

// expectOneWinner checks that exactly one call succeeded and every other
// one failed with loser.
func expectOneWinner(t *testing.T, errs []error, loser error) {
	t.Helper()
	wins := 0
	for _, err := range errs {
		switch {
		case err == nil:
			wins++
		case !errors.Is(err, loser):
			t.Errorf("losing call = %v, want %v", err, loser)
		}
	}
	if wins != 1 {
		t.Fatalf("%d of %d concurrent calls succeeded, want exactly 1", wins, len(errs))
	}
}

// TestConcurrentFinishIsSingleUse submits the same finish request
// concurrently against the real KV store: exactly one may succeed.
func TestConcurrentFinishIsSingleUse(t *testing.T) {
	t.Run("login", func(t *testing.T) {
		h := newSQLiteHarness(t)
		a := newAuthenticator(t)
		h.register("u1", a, "")
		cer, err := h.svc.BeginLogin(h.ctx, "st", h.proof("st"))
		if err != nil {
			t.Fatal(err)
		}
		a.Counter++
		resp := a.Get(cer.Options)
		expectOneWinner(t, race(func() error {
			_, err := h.svc.FinishLogin(h.ctx, cer.Session, resp)
			return err
		}), ErrSessionInvalid)
	})
	t.Run("registration", func(t *testing.T) {
		h := newSQLiteHarness(t)
		cer, err := h.svc.BeginRegistration(h.ctx, "u1", label("u1"), "st")
		if err != nil {
			t.Fatal(err)
		}
		resp := newAuthenticator(t).Create(cer.Options)
		expectOneWinner(t, race(func() error {
			_, _, err := h.svc.FinishRegistration(h.ctx, "u1", cer.Session, "", resp)
			return err
		}), ErrSessionInvalid)
		if list, err := h.svc.Credentials(h.ctx, "u1"); err != nil || len(list) != 1 {
			t.Fatalf("Credentials = %d, %v", len(list), err)
		}
	})
	t.Run("bind", func(t *testing.T) {
		h := newSQLiteHarness(t)
		a := newAuthenticator(t)
		h.register("u1", a, "")
		cer, err := h.svc.BeginBind(h.ctx, "u1", "st")
		if err != nil {
			t.Fatal(err)
		}
		a.Counter++
		resp := a.Get(cer.Options)
		expectOneWinner(t, race(func() error {
			_, err := h.svc.FinishBind(h.ctx, "u1", cer.Session, resp)
			return err
		}), ErrSessionInvalid)
	})
}

// TestConcurrentRedeemIsSingleUse redeems one login token concurrently
// against the real KV store: exactly one may succeed.
func TestConcurrentRedeemIsSingleUse(t *testing.T) {
	h := newSQLiteHarness(t)
	a := newAuthenticator(t)
	h.register("u1", a, "")
	a.Counter++
	redirect, err := h.login(a, "st")
	if err != nil {
		t.Fatal(err)
	}
	state, token := parseRedirect(t, redirect)
	handle := h.handle("u1")
	expectOneWinner(t, race(func() error {
		ext, err := h.svc.RedeemLoginToken(h.ctx, token, state)
		if err == nil && ext != handle {
			return errors.New("redeemed for another handle")
		}
		return err
	}), ErrTokenInvalid)
}

// TestConcurrentRegistrationsRespectLimit finishes several registrations of
// one user at once (different challenges and credentials) while one slot is
// left: exactly one may succeed.
func TestConcurrentRegistrationsRespectLimit(t *testing.T) {
	h := newSQLiteHarness(t)
	for range maxCredentialsPerUser - 1 {
		h.register("u1", newAuthenticator(t), "")
	}
	sessions := make(chan func() error, concurrency)
	for range concurrency {
		cer, err := h.svc.BeginRegistration(h.ctx, "u1", label("u1"), "")
		if err != nil {
			t.Fatal(err)
		}
		resp := newAuthenticator(t).Create(cer.Options)
		sessions <- func() error {
			_, _, err := h.svc.FinishRegistration(h.ctx, "u1", cer.Session, "", resp)
			return err
		}
	}
	expectOneWinner(t, race(func() error { return (<-sessions)() }), ErrCredentialLimit)
	if list, err := h.svc.Credentials(h.ctx, "u1"); err != nil || len(list) != maxCredentialsPerUser {
		t.Fatalf("Credentials = %d, %v; want %d", len(list), err, maxCredentialsPerUser)
	}
}
