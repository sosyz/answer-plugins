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
	"testing"

	"github.com/apache/answer-plugins/connector-passkey/internal/store"
)

func TestBindHappyPath(t *testing.T) {
	h := newHarness(t)
	a, b := newAuthenticator(t), newAuthenticator(t)
	h.register("u1", a, "")
	h.register("u1", b, "")
	cer, err := h.svc.BeginBind(h.ctx, "u1", "bind-state")
	if err != nil {
		t.Fatal(err)
	}
	if n := len(cer.Options.AllowedCredentials); n != 2 {
		t.Fatalf("allowCredentials has %d entries", n)
	}
	b.Counter = 4
	redirect, err := h.svc.FinishBind(h.ctx, "u1", cer.Session, b.Get(cer.Options))
	if err != nil {
		t.Fatal(err)
	}
	state, token := parseRedirect(t, redirect)
	if state != "bind-state" {
		t.Fatalf("state = %q", state)
	}
	if ext, err := h.svc.RedeemLoginToken(h.ctx, token, state); err != nil || ext != h.handle("u1") {
		t.Fatalf("redeem = %q, %v", ext, err)
	}
	if rec := h.record(b.CredentialID); rec.Credential.Authenticator.SignCount != 4 || rec.LastUsedAt.IsZero() {
		t.Fatalf("bind did not update the credential: %+v", rec)
	}
	if _, err := h.svc.FinishBind(h.ctx, "u1", cer.Session, b.Get(cer.Options)); !errors.Is(err, ErrSessionInvalid) {
		t.Fatalf("replayed bind = %v", err)
	}
}

func TestBindWithAnotherUsersPasskey(t *testing.T) {
	h := newHarness(t)
	mine, theirs := newAuthenticator(t), newAuthenticator(t)
	h.register("u1", mine, "")
	h.register("u2", theirs, "")
	cer, err := h.svc.BeginBind(h.ctx, "u1", "st")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.FinishBind(h.ctx, "u1", cer.Session, theirs.Get(cer.Options)); !errors.Is(err, ErrVerificationFailed) {
		t.Fatalf("bind with a foreign passkey = %v", err)
	}
}

func TestBindSessionBelongsToCaller(t *testing.T) {
	h := newHarness(t)
	a, b := newAuthenticator(t), newAuthenticator(t)
	h.register("u1", a, "")
	h.register("u2", b, "")
	cer, err := h.svc.BeginBind(h.ctx, "u1", "st")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.FinishBind(h.ctx, "u2", cer.Session, a.Get(cer.Options)); !errors.Is(err, ErrSessionInvalid) {
		t.Fatalf("bind finished by another user = %v", err)
	}
}

// TestBindHandleChanged: a bind session is tied to the user handle it was
// started for; a handle removed or replaced meanwhile invalidates it.
func TestBindHandleChanged(t *testing.T) {
	for _, tc := range []struct {
		name    string
		replace bool
	}{
		{"handle missing", false},
		{"handle changed", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			a := newAuthenticator(t)
			h.register("u1", a, "")
			cer, err := h.svc.BeginBind(h.ctx, "u1", "st")
			if err != nil {
				t.Fatal(err)
			}
			h.store.Store.(interface{ DeleteRow(string, string) }).DeleteRow(store.GroupUserHandle, "u1")
			if tc.replace {
				if _, err := h.store.EnsureUserHandle(h.ctx, "u1", newUserHandle); err != nil {
					t.Fatal(err)
				}
			}
			a.Counter++
			if _, err := h.svc.FinishBind(h.ctx, "u1", cer.Session, a.Get(cer.Options)); !errors.Is(err, ErrSessionInvalid) {
				t.Fatalf("FinishBind = %v, want ErrSessionInvalid", err)
			}
			if w := h.store.Writes()["SaveCeremonyResult"]; w != 1 {
				t.Fatalf("SaveCeremonyResult ran %d times, want only the registration", w)
			}
		})
	}
}

func TestBindPreconditions(t *testing.T) {
	h := newHarness(t)
	if _, err := h.svc.BeginBind(h.ctx, "u1", ""); !errors.Is(err, ErrStateRequired) {
		t.Fatalf("empty state = %v", err)
	}
	if _, err := h.svc.BeginBind(h.ctx, "u1", "st"); !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("no handle = %v", err)
	}
	a := newAuthenticator(t)
	h.register("u1", a, "")
	if err := h.svc.DeleteCredential(h.ctx, "u1", a.CredentialID); err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.BeginBind(h.ctx, "u1", "st"); !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("no passkeys = %v", err)
	}
}

func TestLoginAfterDeleteFails(t *testing.T) {
	h := newHarness(t)
	a := newAuthenticator(t)
	h.register("u1", a, "")
	if err := h.svc.DeleteCredential(h.ctx, "u1", a.CredentialID); err != nil {
		t.Fatal(err)
	}
	if _, err := h.login(a, "st"); !errors.Is(err, ErrVerificationFailed) {
		t.Fatalf("login with deleted passkey = %v", err)
	}
	if list, _ := h.svc.Credentials(h.ctx, "u1"); len(list) != 0 {
		t.Fatalf("deleted passkey still listed: %+v", list)
	}
}
