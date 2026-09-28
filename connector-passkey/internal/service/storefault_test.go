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
	"sync"
	"testing"
	"time"

	"github.com/apache/answer-plugins/connector-passkey/internal/store"
	"github.com/apache/answer-plugins/connector-passkey/internal/store/storetest"
)

var errBoom = errors.New("store is down")

// faultStore wraps a Store: a method listed in fail returns that error, and a
// hook registered for a method runs before the call with its 1-based call
// number. Hooks run without faultStore's lock and should use Inner.
type faultStore struct {
	store.Store
	mu    sync.Mutex
	fail  map[string]error
	hooks map[string]func(call int)
	calls map[string]int
	// beforeSave runs before SaveCeremonyResult is failed or forwarded.
	beforeSave func(r store.CeremonyResult)
}

func newFaultStore() *faultStore {
	return &faultStore{
		Store: storetest.NewMemory(),
		fail:  map[string]error{},
		hooks: map[string]func(int){},
		calls: map[string]int{},
	}
}

func (f *faultStore) Inner() store.Store { return f.Store }

func (f *faultStore) failOn(method string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fail[method] = err
}

func (f *faultStore) hook(method string, fn func(call int)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hooks[method] = fn
}

func (f *faultStore) callCount(method string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[method]
}

func (f *faultStore) enter(method string) error {
	f.mu.Lock()
	f.calls[method]++
	n, hook, err := f.calls[method], f.hooks[method], f.fail[method]
	f.mu.Unlock()
	if hook != nil {
		hook(n)
	}
	return err
}

// DeleteRow forwards to the memory store (see TestRegistrationHandleChanged).
func (f *faultStore) DeleteRow(group, key string) {
	f.Store.(interface{ DeleteRow(string, string) }).DeleteRow(group, key)
}

func (f *faultStore) CeremonyKey(ctx context.Context) ([]byte, error) {
	if err := f.enter("CeremonyKey"); err != nil {
		return nil, err
	}
	return f.Store.CeremonyKey(ctx)
}

func (f *faultStore) UserHandle(ctx context.Context, id string) (string, error) {
	if err := f.enter("UserHandle"); err != nil {
		return "", err
	}
	return f.Store.UserHandle(ctx, id)
}

func (f *faultStore) EnsureUserHandle(ctx context.Context, id string, gen func() (string, error)) (string, error) {
	if err := f.enter("EnsureUserHandle"); err != nil {
		return "", err
	}
	return f.Store.EnsureUserHandle(ctx, id, gen)
}

func (f *faultStore) Credential(ctx context.Context, id []byte) (store.CredentialRecord, error) {
	if err := f.enter("Credential"); err != nil {
		return store.CredentialRecord{}, err
	}
	return f.Store.Credential(ctx, id)
}

func (f *faultStore) Credentials(ctx context.Context, h string) ([]store.CredentialRecord, error) {
	if err := f.enter("Credentials"); err != nil {
		return nil, err
	}
	return f.Store.Credentials(ctx, h)
}

func (f *faultStore) RenameCredential(ctx context.Context, rec store.CredentialRecord) error {
	if err := f.enter("RenameCredential"); err != nil {
		return err
	}
	return f.Store.RenameCredential(ctx, rec)
}

func (f *faultStore) DeleteCredential(ctx context.Context, h string, id []byte) error {
	if err := f.enter("DeleteCredential"); err != nil {
		return err
	}
	return f.Store.DeleteCredential(ctx, h, id)
}

func (f *faultStore) ChallengeConsumed(ctx context.Context, c string) (bool, error) {
	if err := f.enter("ChallengeConsumed"); err != nil {
		return false, err
	}
	return f.Store.ChallengeConsumed(ctx, c)
}

func (f *faultStore) SaveCeremonyResult(ctx context.Context, r store.CeremonyResult) error {
	err := f.enter("SaveCeremonyResult")
	f.mu.Lock()
	before := f.beforeSave
	f.mu.Unlock()
	if before != nil {
		before(r)
	}
	if err != nil {
		return err
	}
	return f.Store.SaveCeremonyResult(ctx, r)
}

func (f *faultStore) TakeLoginToken(ctx context.Context, h string) (store.LoginToken, error) {
	if err := f.enter("TakeLoginToken"); err != nil {
		return store.LoginToken{}, err
	}
	return f.Store.TakeLoginToken(ctx, h)
}

func (f *faultStore) PurgeExpired(ctx context.Context, now time.Time) error {
	if err := f.enter("PurgeExpired"); err != nil {
		return err
	}
	return f.Store.PurgeExpired(ctx, now)
}

// sentinels are every error the HTTP adapter maps to a non-500 reason.
var sentinels = []error{
	ErrNotConfigured, ErrInvalidInput, ErrStateRequired, ErrStateUnverified, ErrInvalidName,
	ErrSessionInvalid, ErrVerificationFailed, ErrCloneDetected, ErrCredentialExists,
	ErrCredentialLimit, ErrCredentialNotFound, ErrTokenInvalid,
}

// TestStoreErrorsAreInternal fails one store method at a time and checks
// that the error surfaces wrapped (500 internal_error), never as a sentinel
// that would blame the client (for example verification_failed for a
// database outage).
func TestStoreErrorsAreInternal(t *testing.T) {
	type env struct {
		h  *harness
		fs *faultStore
		a  *authenticator
	}
	// loginSession returns a login session and a response for it.
	loginSession := func(e env) (string, []byte) {
		cer, err := e.h.svc.BeginLogin(e.h.ctx, "st", e.h.proof("st"))
		if err != nil {
			e.h.t.Fatal(err)
		}
		e.a.Counter++
		return cer.Session, e.a.Get(cer.Options)
	}
	for _, tc := range []struct {
		name, method string
		// run prepares the operation, then calls fail and runs it.
		run func(e env, fail func()) error
	}{
		{"BeginLogin", "CeremonyKey", func(e env, fail func()) error {
			proof := e.h.proof("st")
			fail()
			_, err := e.h.svc.BeginLogin(e.h.ctx, "st", proof)
			return err
		}},
		{"FinishLogin", "CeremonyKey", func(e env, fail func()) error {
			session, resp := loginSession(e)
			fail()
			_, err := e.h.svc.FinishLogin(e.h.ctx, session, resp)
			return err
		}},
		{"FinishLogin", "ChallengeConsumed", func(e env, fail func()) error {
			session, resp := loginSession(e)
			fail()
			_, err := e.h.svc.FinishLogin(e.h.ctx, session, resp)
			return err
		}},
		{"FinishLogin", "Credential", func(e env, fail func()) error {
			session, resp := loginSession(e)
			fail()
			_, err := e.h.svc.FinishLogin(e.h.ctx, session, resp)
			return err
		}},
		{"FinishLogin", "SaveCeremonyResult", func(e env, fail func()) error {
			session, resp := loginSession(e)
			fail()
			_, err := e.h.svc.FinishLogin(e.h.ctx, session, resp)
			return err
		}},
		{"BeginRegistration", "EnsureUserHandle", func(e env, fail func()) error {
			fail()
			_, err := e.h.svc.BeginRegistration(e.h.ctx, "u2", label("u2"), "")
			return err
		}},
		{"BeginRegistration", "Credentials", func(e env, fail func()) error {
			fail()
			_, err := e.h.svc.BeginRegistration(e.h.ctx, "u1", label("u1"), "")
			return err
		}},
		{"FinishRegistration", "UserHandle", func(e env, fail func()) error {
			cer, err := e.h.svc.BeginRegistration(e.h.ctx, "u1", label("u1"), "")
			if err != nil {
				return err
			}
			fail()
			_, _, err = e.h.svc.FinishRegistration(e.h.ctx, "u1", cer.Session, "", newAuthenticator(e.h.t).Create(cer.Options))
			return err
		}},
		{"FinishRegistration", "Credential", func(e env, fail func()) error {
			cer, err := e.h.svc.BeginRegistration(e.h.ctx, "u1", label("u1"), "")
			if err != nil {
				return err
			}
			fail()
			_, _, err = e.h.svc.FinishRegistration(e.h.ctx, "u1", cer.Session, "", newAuthenticator(e.h.t).Create(cer.Options))
			return err
		}},
		{"FinishRegistration", "SaveCeremonyResult", func(e env, fail func()) error {
			cer, err := e.h.svc.BeginRegistration(e.h.ctx, "u1", label("u1"), "st")
			if err != nil {
				return err
			}
			fail()
			_, _, err = e.h.svc.FinishRegistration(e.h.ctx, "u1", cer.Session, "", newAuthenticator(e.h.t).Create(cer.Options))
			return err
		}},
		{"BeginBind", "Credentials", func(e env, fail func()) error {
			fail()
			_, err := e.h.svc.BeginBind(e.h.ctx, "u1", "st")
			return err
		}},
		{"FinishBind", "UserHandle", func(e env, fail func()) error {
			cer, err := e.h.svc.BeginBind(e.h.ctx, "u1", "st")
			if err != nil {
				return err
			}
			e.a.Counter++
			resp := e.a.Get(cer.Options)
			fail()
			_, err = e.h.svc.FinishBind(e.h.ctx, "u1", cer.Session, resp)
			return err
		}},
		{"RedeemLoginToken", "TakeLoginToken", func(e env, fail func()) error {
			session, resp := loginSession(e)
			redirect, err := e.h.svc.FinishLogin(e.h.ctx, session, resp)
			if err != nil {
				return err
			}
			state, token := parseRedirect(e.h.t, redirect)
			fail()
			_, err = e.h.svc.RedeemLoginToken(e.h.ctx, token, state)
			return err
		}},
		{"Credentials", "UserHandle", func(e env, fail func()) error {
			fail()
			_, err := e.h.svc.Credentials(e.h.ctx, "u1")
			return err
		}},
		{"RenameCredential", "Credential", func(e env, fail func()) error {
			fail()
			_, err := e.h.svc.RenameCredential(e.h.ctx, "u1", e.a.CredentialID, "new")
			return err
		}},
		{"RenameCredential", "RenameCredential", func(e env, fail func()) error {
			fail()
			_, err := e.h.svc.RenameCredential(e.h.ctx, "u1", e.a.CredentialID, "new")
			return err
		}},
		{"DeleteCredential", "DeleteCredential", func(e env, fail func()) error {
			fail()
			return e.h.svc.DeleteCredential(e.h.ctx, "u1", e.a.CredentialID)
		}},
	} {
		t.Run(tc.name+"/"+tc.method, func(t *testing.T) {
			fs := newFaultStore()
			h := newHarnessOn(t, fs)
			a := newAuthenticator(t)
			h.register("u1", a, "")
			err := tc.run(env{h: h, fs: fs, a: a}, func() { fs.failOn(tc.method, errBoom) })
			if !errors.Is(err, errBoom) {
				t.Fatalf("error = %v, want the store error wrapped", err)
			}
			for _, s := range sentinels {
				if errors.Is(err, s) {
					t.Fatalf("store error reported as %v", s)
				}
			}
		})
	}
}

// TestPurgeErrorIsIgnored: a failing purge does not fail the sign-in.
func TestPurgeErrorIsIgnored(t *testing.T) {
	fs := newFaultStore()
	h := newHarnessOn(t, fs)
	a := newAuthenticator(t)
	fs.failOn("PurgeExpired", errBoom)
	h.register("u1", a, "")
	if _, err := h.login(a, "st"); err != nil {
		t.Fatal(err)
	}
	if fs.callCount("PurgeExpired") == 0 {
		t.Fatal("purge did not run")
	}
}

// TestPurgeThrottled: finish and redeem calls purge at most once per
// purgeInterval.
func TestPurgeThrottled(t *testing.T) {
	fs := newFaultStore()
	h := newHarnessOn(t, fs)
	a := newAuthenticator(t)
	h.register("u1", a, "") // first purge
	for range 3 {
		a.Counter++
		redirect, err := h.login(a, "st")
		if err != nil {
			t.Fatal(err)
		}
		state, token := parseRedirect(t, redirect)
		if _, err := h.svc.RedeemLoginToken(h.ctx, token, state); err != nil {
			t.Fatal(err)
		}
	}
	if n := fs.callCount("PurgeExpired"); n != 1 {
		t.Fatalf("PurgeExpired ran %d times within one interval", n)
	}
	h.clock.Advance(purgeInterval)
	a.Counter++
	if _, err := h.login(a, "st"); err != nil {
		t.Fatal(err)
	}
	if n := fs.callCount("PurgeExpired"); n != 2 {
		t.Fatalf("PurgeExpired ran %d times after the interval, want 2", n)
	}
}

// TestSaveFailureAfterConcurrentFinish: when the transaction fails because
// another finish call (another instance) consumed the challenge meanwhile,
// the loser is a replay, not an internal error.
func TestSaveFailureAfterConcurrentFinish(t *testing.T) {
	t.Run("login", func(t *testing.T) {
		fs := newFaultStore()
		h := newHarnessOn(t, fs)
		a := newAuthenticator(t)
		h.register("u1", a, "")
		fs.beforeSave = func(r store.CeremonyResult) {
			if err := fs.Inner().SaveCeremonyResult(context.Background(), r); err != nil {
				t.Error(err)
			}
		}
		fs.failOn("SaveCeremonyResult", errBoom)
		a.Counter++
		if _, err := h.login(a, "st"); !errors.Is(err, ErrSessionInvalid) {
			t.Fatalf("FinishLogin = %v, want ErrSessionInvalid", err)
		}
	})
	t.Run("registration", func(t *testing.T) {
		fs := newFaultStore()
		h := newHarnessOn(t, fs)
		cer, err := h.svc.BeginRegistration(h.ctx, "u1", label("u1"), "")
		if err != nil {
			t.Fatal(err)
		}
		fs.beforeSave = func(r store.CeremonyResult) {
			if err := fs.Inner().SaveCeremonyResult(context.Background(), r); err != nil {
				t.Error(err)
			}
		}
		fs.failOn("SaveCeremonyResult", errBoom)
		if _, _, err := h.svc.FinishRegistration(h.ctx, "u1", cer.Session, "", newAuthenticator(t).Create(cer.Options)); !errors.Is(err, ErrSessionInvalid) {
			t.Fatalf("FinishRegistration = %v, want ErrSessionInvalid", err)
		}
	})
}

// TestSaveFailureAfterConcurrentRegistration: when the transaction fails
// because another instance registered the same credential ID meanwhile, the
// loser gets credential_exists.
func TestSaveFailureAfterConcurrentRegistration(t *testing.T) {
	fs := newFaultStore()
	h := newHarnessOn(t, fs)
	cer, err := h.svc.BeginRegistration(h.ctx, "u1", label("u1"), "")
	if err != nil {
		t.Fatal(err)
	}
	fs.beforeSave = func(r store.CeremonyResult) {
		r.Challenge = "another ceremony"
		r.Credential.UserHandle = "another handle"
		if err := fs.Inner().SaveCeremonyResult(context.Background(), r); err != nil {
			t.Error(err)
		}
	}
	fs.failOn("SaveCeremonyResult", errBoom)
	if _, _, err := h.svc.FinishRegistration(h.ctx, "u1", cer.Session, "", newAuthenticator(t).Create(cer.Options)); !errors.Is(err, ErrCredentialExists) {
		t.Fatalf("FinishRegistration = %v, want ErrCredentialExists", err)
	}
}

// TestRenameFailureAfterConcurrentDelete: a rename whose write fails because
// the passkey was deleted meanwhile reports credential_not_found.
func TestRenameFailureAfterConcurrentDelete(t *testing.T) {
	fs := newFaultStore()
	h := newHarnessOn(t, fs)
	a := newAuthenticator(t)
	h.register("u1", a, "")
	handle := h.handle("u1")
	fs.hook("RenameCredential", func(int) {
		if err := fs.Inner().DeleteCredential(context.Background(), handle, a.CredentialID); err != nil {
			t.Error(err)
		}
	})
	fs.failOn("RenameCredential", errBoom)
	if _, err := h.svc.RenameCredential(h.ctx, "u1", a.CredentialID, "new"); !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("RenameCredential = %v, want ErrCredentialNotFound", err)
	}
}

// TestLoginRereadsCredential changes the stored record between verification
// and the save (the hook runs on the locked re-check of the challenge).
func TestLoginRereadsCredential(t *testing.T) {
	setup := func(t *testing.T) (*harness, *faultStore, *authenticator) {
		fs := newFaultStore()
		h := newHarnessOn(t, fs)
		a := newAuthenticator(t)
		h.register("u1", a, "")
		return h, fs, a
	}
	// onRecheck runs fn on the second ChallengeConsumed call of the next
	// login, the one right before the save.
	onRecheck := func(fs *faultStore, fn func()) {
		base := fs.callCount("ChallengeConsumed")
		fs.hook("ChallengeConsumed", func(n int) {
			if n == base+2 {
				fn()
			}
		})
	}

	t.Run("deleted passkey is not resurrected", func(t *testing.T) {
		h, fs, a := setup(t)
		handle := h.handle("u1")
		onRecheck(fs, func() {
			if err := fs.Inner().DeleteCredential(context.Background(), handle, a.CredentialID); err != nil {
				t.Error(err)
			}
		})
		a.Counter++
		if _, err := h.login(a, "st"); !errors.Is(err, ErrVerificationFailed) {
			t.Fatalf("login = %v, want ErrVerificationFailed", err)
		}
		if _, err := fs.Inner().Credential(h.ctx, a.CredentialID); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("deleted passkey was written back: %v", err)
		}
	})

	t.Run("concurrent rename is kept", func(t *testing.T) {
		h, fs, a := setup(t)
		onRecheck(fs, func() {
			rec := h.record(a.CredentialID)
			rec.Name = "Renamed"
			if err := fs.Inner().RenameCredential(context.Background(), rec); err != nil {
				t.Error(err)
			}
		})
		a.Counter = 7
		if _, err := h.login(a, "st"); err != nil {
			t.Fatal(err)
		}
		rec := h.record(a.CredentialID)
		if rec.Name != "Renamed" || rec.Credential.Authenticator.SignCount != 7 || rec.LastUsedAt.IsZero() {
			t.Fatalf("record after login = name %q count %d last used %v", rec.Name, rec.Credential.Authenticator.SignCount, rec.LastUsedAt)
		}
	})

	t.Run("counter raised meanwhile is a clone", func(t *testing.T) {
		h, fs, a := setup(t)
		onRecheck(fs, func() {
			rec := h.record(a.CredentialID)
			rec.Credential.Authenticator.SignCount = 50
			if err := fs.Inner().RenameCredential(context.Background(), rec); err != nil {
				t.Error(err)
			}
		})
		a.Counter = 7
		if _, err := h.login(a, "st"); !errors.Is(err, ErrCloneDetected) {
			t.Fatalf("login = %v, want ErrCloneDetected", err)
		}
		if n := h.record(a.CredentialID).Credential.Authenticator.SignCount; n != 50 {
			t.Fatalf("sign counter rolled back to %d", n)
		}
	})
}

// TestRenameKeepsConcurrentLogin runs a sign-in while a rename is between
// its read and its write: the final record has both the new name and the
// new sign counter.
func TestRenameKeepsConcurrentLogin(t *testing.T) {
	fs := newFaultStore()
	h := newHarnessOn(t, fs)
	a := newAuthenticator(t)
	h.register("u1", a, "")
	cer, err := h.svc.BeginLogin(h.ctx, "st", h.proof("st"))
	if err != nil {
		t.Fatal(err)
	}
	a.Counter = 9
	resp := a.Get(cer.Options)

	done := make(chan error, 1)
	fs.hook("RenameCredential", func(int) {
		go func() {
			_, err := h.svc.FinishLogin(h.ctx, cer.Session, resp)
			done <- err
		}()
	})
	if _, err := h.svc.RenameCredential(h.ctx, "u1", a.CredentialID, "Work"); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	rec := h.record(a.CredentialID)
	if rec.Name != "Work" || rec.Credential.Authenticator.SignCount != 9 {
		t.Fatalf("record = name %q count %d", rec.Name, rec.Credential.Authenticator.SignCount)
	}
}
