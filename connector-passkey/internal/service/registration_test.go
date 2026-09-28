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
	"bytes"
	"errors"
	"testing"

	"github.com/apache/answer-plugins/connector-passkey/internal/store"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

func TestRegistrationHappyPath(t *testing.T) {
	h := newHarness(t)
	a := newAuthenticator(t)
	cer, err := h.svc.BeginRegistration(h.ctx, "u1", UserLabel{Name: "alice"}, "")
	if err != nil {
		t.Fatal(err)
	}
	o := cer.Options
	sel := o.AuthenticatorSelection
	if sel.ResidentKey != protocol.ResidentKeyRequirementRequired || sel.RequireResidentKey == nil || !*sel.RequireResidentKey ||
		sel.UserVerification != protocol.VerificationRequired || o.Attestation != protocol.PreferNoAttestation ||
		o.Timeout != 300000 || o.RelyingParty.ID != testRPID || o.User.Name != "alice" || o.User.DisplayName != "alice" ||
		len(o.CredentialExcludeList) != 0 {
		t.Fatalf("unexpected creation options %+v", o)
	}
	handle := h.handle("u1")
	if uid := o.User.ID.(protocol.URLEncodedBase64); b64(uid) != handle || len(uid) != 32 {
		t.Fatalf("user.id %x does not match handle %q", uid, handle)
	}

	cred, redirect, err := h.svc.FinishRegistration(h.ctx, "u1", cer.Session, "  Laptop\n", a.Create(o))
	if err != nil {
		t.Fatal(err)
	}
	if redirect != "" {
		t.Fatalf("redirect without state = %q", redirect)
	}
	if !bytes.Equal(cred.ID, a.CredentialID) || cred.Name != "Laptop" || !cred.CreatedAt.Equal(h.clock.Now()) || !cred.LastUsedAt.IsZero() || !cred.BackupEligible || !cred.BackupState {
		t.Fatalf("unexpected credential view %+v", cred)
	}
	rec := h.record(a.CredentialID)
	if rec.UserHandle != handle || rec.Credential.AttestationFormat != "none" || len(rec.Credential.Transport) != 2 || len(rec.Credential.PublicKey) == 0 {
		t.Fatalf("unexpected record %+v", rec)
	}
	list, err := h.store.Credentials(h.ctx, handle)
	if err != nil || len(list) != 1 {
		t.Fatalf("membership missing: %v %v", list, err)
	}
	var sd = mustOpen(t, h, cer.Session, purposeRegister)
	if used, _ := h.store.ChallengeConsumed(h.ctx, sd.Data.Challenge); !used {
		t.Fatal("challenge not consumed")
	}
	// Replay.
	if _, _, err := h.svc.FinishRegistration(h.ctx, "u1", cer.Session, "", a.Create(o)); !errors.Is(err, ErrSessionInvalid) {
		t.Fatalf("replayed registration = %v", err)
	}
}

func mustOpen(t *testing.T, h *harness, session, purpose string) ceremonyState {
	t.Helper()
	st, err := h.svc.open(h.ctx, session, purpose)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func TestRegistrationWithStateReturnsRedirect(t *testing.T) {
	h := newHarness(t)
	a := newAuthenticator(t)
	_, redirect := h.register("u1", a, "bind-state")
	state, token := parseRedirect(t, redirect)
	if state != "bind-state" {
		t.Fatalf("state = %q", state)
	}
	if ext, err := h.svc.RedeemLoginToken(h.ctx, token, "bind-state"); err != nil || ext != h.handle("u1") {
		t.Fatalf("redeem = %q, %v", ext, err)
	}
}

func TestRegistrationOtherUser(t *testing.T) {
	h := newHarness(t)
	a := newAuthenticator(t)
	cer, err := h.svc.BeginRegistration(h.ctx, "u1", label("u1"), "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.BeginRegistration(h.ctx, "u2", label("u2"), ""); err != nil {
		t.Fatal(err)
	}
	if _, _, err := h.svc.FinishRegistration(h.ctx, "u2", cer.Session, "", a.Create(cer.Options)); !errors.Is(err, ErrSessionInvalid) {
		t.Fatalf("finish by another user = %v", err)
	}
}

func TestRegistrationHandleChanged(t *testing.T) {
	h := newHarness(t)
	a := newAuthenticator(t)
	cer, err := h.svc.BeginRegistration(h.ctx, "u1", label("u1"), "")
	if err != nil {
		t.Fatal(err)
	}
	h.store.Store.(interface{ DeleteRow(string, string) }).DeleteRow(store.GroupUserHandle, "u1")
	if _, err := h.store.EnsureUserHandle(h.ctx, "u1", newUserHandle); err != nil {
		t.Fatal(err)
	}
	if _, _, err := h.svc.FinishRegistration(h.ctx, "u1", cer.Session, "", a.Create(cer.Options)); !errors.Is(err, ErrSessionInvalid) {
		t.Fatalf("finish after handle change = %v", err)
	}
}

func TestRegistrationDuplicateCredentialID(t *testing.T) {
	h := newHarness(t)
	a := newAuthenticator(t)
	h.register("u1", a, "")
	cer, err := h.svc.BeginRegistration(h.ctx, "u2", label("u2"), "")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := h.svc.FinishRegistration(h.ctx, "u2", cer.Session, "", a.Create(cer.Options)); !errors.Is(err, ErrCredentialExists) {
		t.Fatalf("duplicate credential ID = %v", err)
	}
	if rec := h.record(a.CredentialID); rec.UserHandle != h.handle("u1") {
		t.Fatal("duplicate registration changed the owner")
	}
}

func TestRegistrationExcludesExisting(t *testing.T) {
	h := newHarness(t)
	a, b := newAuthenticator(t), newAuthenticator(t)
	h.register("u1", a, "")
	h.register("u1", b, "")
	cer, err := h.svc.BeginRegistration(h.ctx, "u1", label("u1"), "")
	if err != nil {
		t.Fatal(err)
	}
	ex := cer.Options.CredentialExcludeList
	if len(ex) != 2 {
		t.Fatalf("exclude list = %+v", ex)
	}
	for _, d := range ex {
		if !bytes.Equal(d.CredentialID, a.CredentialID) && !bytes.Equal(d.CredentialID, b.CredentialID) {
			t.Fatalf("unexpected excluded id %x", d.CredentialID)
		}
		if d.Type != protocol.PublicKeyCredentialType || len(d.Transport) != 2 {
			t.Fatalf("descriptor lacks type/transports: %+v", d)
		}
	}
}

func TestRegistrationLimit(t *testing.T) {
	h := newHarness(t)
	for i := 0; i < maxCredentialsPerUser-1; i++ {
		h.register("u1", newAuthenticator(t), "")
	}
	// Two ceremonies started at 19 passkeys: only one may finish.
	c1, err := h.svc.BeginRegistration(h.ctx, "u1", label("u1"), "")
	if err != nil {
		t.Fatal(err)
	}
	c2, err := h.svc.BeginRegistration(h.ctx, "u1", label("u1"), "")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := h.svc.FinishRegistration(h.ctx, "u1", c1.Session, "", newAuthenticator(t).Create(c1.Options)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := h.svc.FinishRegistration(h.ctx, "u1", c2.Session, "", newAuthenticator(t).Create(c2.Options)); !errors.Is(err, ErrCredentialLimit) {
		t.Fatalf("finish over the limit = %v", err)
	}
	if _, err := h.svc.BeginRegistration(h.ctx, "u1", label("u1"), ""); !errors.Is(err, ErrCredentialLimit) {
		t.Fatalf("begin at the limit = %v", err)
	}
}

func TestRegistrationInput(t *testing.T) {
	h := newHarness(t)
	if _, err := h.svc.BeginRegistration(h.ctx, "u1", UserLabel{Name: " \t"}, ""); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("empty user_name = %v", err)
	}
	cer, err := h.svc.BeginRegistration(h.ctx, "u1", label("u1"), "")
	if err != nil {
		t.Fatal(err)
	}
	a := newAuthenticator(t)
	if _, _, err := h.svc.FinishRegistration(h.ctx, "u1", cer.Session, string(bytes.Repeat([]byte("x"), 65)), a.Create(cer.Options)); !errors.Is(err, ErrInvalidName) {
		t.Fatalf("long name = %v", err)
	}
	if _, _, err := h.svc.FinishRegistration(h.ctx, "u1", cer.Session, "", []byte(`{"id":"x"}`)); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("garbage credential = %v", err)
	}
	// A response for another origin fails verification.
	a.Origin = "https://evil.example.org"
	if _, _, err := h.svc.FinishRegistration(h.ctx, "u1", cer.Session, "", a.Create(cer.Options)); !errors.Is(err, ErrVerificationFailed) {
		t.Fatalf("foreign origin = %v", err)
	}
}

func TestNotConfigured(t *testing.T) {
	h := newHarness(t)
	h.svc.relyingParty = func() (*webauthn.WebAuthn, error) { return nil, errors.New("no site url") }
	if _, err := h.svc.BeginLogin(h.ctx, "st", ""); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("BeginLogin = %v", err)
	}
	if _, err := h.svc.BeginRegistration(h.ctx, "u1", label("u1"), ""); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("BeginRegistration = %v", err)
	}
	if w := h.store.Writes(); len(w) != 0 {
		t.Fatalf("unconfigured begin wrote %v", w)
	}
}
