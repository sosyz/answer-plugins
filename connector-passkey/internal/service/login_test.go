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
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
)

// parseRedirect parses a receiver URL and returns its state and token.
func parseRedirect(t *testing.T, redirect string) (state, token string) {
	t.Helper()
	const prefix = testReceiver + "?"
	if !strings.HasPrefix(redirect, prefix) {
		t.Fatalf("redirect %q does not start with %q", redirect, prefix)
	}
	u, err := url.Parse(redirect)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if len(q) != 2 || q.Get("token") == "" {
		t.Fatalf("unexpected redirect query %q", u.RawQuery)
	}
	return q.Get("state"), q.Get("token")
}

func TestLoginHappyPath(t *testing.T) {
	h := newHarness(t)
	a := newAuthenticator(t)
	h.register("u1", a, "")
	handle := h.handle("u1")

	const state = "core state/with?chars&="
	redirect, err := h.login(a, state)
	if err != nil {
		t.Fatalf("FinishLogin: %v", err)
	}
	gotState, token := parseRedirect(t, redirect)
	if gotState != state {
		t.Fatalf("redirect state = %q", gotState)
	}
	if !strings.Contains(redirect, "state="+url.QueryEscape(state)+"&token=") {
		t.Fatalf("redirect %q is not in the documented form", redirect)
	}
	ext, err := h.svc.RedeemLoginToken(h.ctx, token, state)
	if err != nil || ext != handle {
		t.Fatalf("RedeemLoginToken = %q, %v; want %q", ext, err, handle)
	}
	if _, err := h.svc.RedeemLoginToken(h.ctx, token, state); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("second redeem = %v, want ErrTokenInvalid", err)
	}

	// Wrong state burns the token.
	redirect, err = h.login(a, "s2")
	if err != nil {
		t.Fatal(err)
	}
	_, token = parseRedirect(t, redirect)
	if _, err := h.svc.RedeemLoginToken(h.ctx, token, "other"); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("wrong state redeem = %v", err)
	}
	if _, err := h.svc.RedeemLoginToken(h.ctx, token, "s2"); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("redeem after wrong state = %v", err)
	}

	// Expired token.
	redirect, err = h.login(a, "s3")
	if err != nil {
		t.Fatal(err)
	}
	_, token = parseRedirect(t, redirect)
	h.clock.Advance(tokenTTL + time.Second)
	if _, err := h.svc.RedeemLoginToken(h.ctx, token, "s3"); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("expired redeem = %v", err)
	}
}

func TestBeginLoginWritesNothing(t *testing.T) {
	h := newHarness(t)
	cer, err := h.svc.BeginLogin(h.ctx, "state", h.proof("state"))
	if err != nil {
		t.Fatal(err)
	}
	if w := h.store.Writes(); len(w) != 0 {
		t.Fatalf("BeginLogin wrote %v", w)
	}
	o := cer.Options
	if len(o.AllowedCredentials) != 0 || o.UserVerification != protocol.VerificationRequired || o.Timeout != 300000 || o.RelyingPartyID != testRPID {
		t.Fatalf("unexpected login options %+v", o)
	}
}

func TestBeginLoginRequiresState(t *testing.T) {
	h := newHarness(t)
	if _, err := h.svc.BeginLogin(h.ctx, "", ""); !errors.Is(err, ErrStateRequired) {
		t.Fatalf("BeginLogin(\"\") = %v", err)
	}
	if _, err := h.svc.BeginLogin(h.ctx, strings.Repeat("s", maxStateBytes+1), ""); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("BeginLogin(long) = %v", err)
	}
}

func TestLoginReplay(t *testing.T) {
	h := newHarness(t)
	a := newAuthenticator(t)
	h.register("u1", a, "")
	cer, err := h.svc.BeginLogin(h.ctx, "st", h.proof("st"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.FinishLogin(h.ctx, cer.Session, a.Get(cer.Options)); err != nil {
		t.Fatal(err)
	}
	a.Counter++
	if _, err := h.svc.FinishLogin(h.ctx, cer.Session, a.Get(cer.Options)); !errors.Is(err, ErrSessionInvalid) {
		t.Fatalf("replayed login = %v, want ErrSessionInvalid", err)
	}
}

func TestLoginUnknownCredential(t *testing.T) {
	h := newHarness(t)
	a := newAuthenticator(t)
	a.UserHandle = []byte("some handle")
	if _, err := h.login(a, "st"); !errors.Is(err, ErrVerificationFailed) {
		t.Fatalf("unknown credential login = %v", err)
	}
	if w := h.store.Writes()["SaveCeremonyResult"]; w != 0 {
		t.Fatalf("failed login persisted %d results", w)
	}
}

func TestLoginUserHandleMismatch(t *testing.T) {
	h := newHarness(t)
	a := newAuthenticator(t)
	b := newAuthenticator(t)
	h.register("u1", a, "")
	h.register("u2", b, "")
	a.UserHandle = b.UserHandle // claims to be u2 with u1's credential
	if _, err := h.login(a, "st"); !errors.Is(err, ErrVerificationFailed) {
		t.Fatalf("mismatched user handle login = %v", err)
	}
}

func TestLoginCloneDetected(t *testing.T) {
	h := newHarness(t)
	a := newAuthenticator(t)
	a.Counter = 5
	h.register("u1", a, "")
	saves := h.store.Writes()["SaveCeremonyResult"]
	a.Counter = 3
	if _, err := h.login(a, "st"); !errors.Is(err, ErrCloneDetected) {
		t.Fatalf("regressed counter login = %v, want ErrCloneDetected", err)
	}
	rec := h.record(a.CredentialID)
	if rec.Credential.Authenticator.SignCount != 5 || rec.Credential.Authenticator.CloneWarning || !rec.LastUsedAt.IsZero() {
		t.Fatalf("stored credential changed: %+v", rec.Credential.Authenticator)
	}
	if got := h.store.Writes()["SaveCeremonyResult"]; got != saves {
		t.Fatalf("clone rejection persisted a result")
	}
}

func TestLoginPersistsCounterAndFlags(t *testing.T) {
	h := newHarness(t)
	a := newAuthenticator(t)
	a.BackupState = false
	a.Counter = 1
	h.register("u1", a, "")
	if rec := h.record(a.CredentialID); rec.Credential.Flags.BackupState || !rec.Credential.Flags.BackupEligible {
		t.Fatalf("registration flags = %+v", rec.Credential.Flags)
	}
	a.BackupState = true
	a.Counter = 10
	h.clock.Advance(time.Minute)
	if _, err := h.login(a, "st"); err != nil {
		t.Fatal(err)
	}
	rec := h.record(a.CredentialID)
	if !rec.Credential.Flags.BackupState || rec.Credential.Authenticator.SignCount != 10 || !rec.LastUsedAt.Equal(h.clock.Now()) {
		t.Fatalf("login did not persist counter/flags: %+v %+v last used %v", rec.Credential.Flags, rec.Credential.Authenticator, rec.LastUsedAt)
	}
	views, err := h.svc.Credentials(h.ctx, "u1")
	if err != nil || len(views) != 1 || !views[0].BackupState || !views[0].BackupEligible || views[0].LastUsedAt.IsZero() {
		t.Fatalf("Credentials = %+v, %v", views, err)
	}
}

func TestBeginLoginRequiresStateProof(t *testing.T) {
	h := newHarness(t)
	proof := h.proof("S1")
	if other := h.proof("S2"); other == proof {
		t.Fatal("proofs for different states are equal")
	}
	cases := []struct {
		name, state, proof string
	}{
		{"missing", "S1", ""},
		{"other state", "S2", proof},
		{"not base64url", "S1", "!!!"},
		{"too long", "S1", strings.Repeat("A", maxProofLen+1)},
		{"truncated", "S1", proof[:len(proof)-1]},
	}
	for _, c := range cases {
		if _, err := h.svc.BeginLogin(h.ctx, c.state, c.proof); !errors.Is(err, ErrStateUnverified) {
			t.Errorf("%s: BeginLogin = %v, want ErrStateUnverified", c.name, err)
		}
	}
	if _, err := h.svc.BeginLogin(h.ctx, "S1", proof); err != nil {
		t.Fatalf("BeginLogin with proof = %v", err)
	}
}
