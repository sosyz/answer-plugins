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
	"strings"
	"testing"
	"time"

	"github.com/apache/answer-plugins/connector-passkey/internal/store"
)

func TestCredentialsNeverCreatesHandle(t *testing.T) {
	h := newHarness(t)
	list, err := h.svc.Credentials(h.ctx, "u1")
	if err != nil || list == nil || len(list) != 0 {
		t.Fatalf("Credentials = %#v, %v", list, err)
	}
	if _, err := h.store.UserHandle(h.ctx, "u1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("listing created a handle: %v", err)
	}
	if w := h.store.Writes(); len(w) != 0 {
		t.Fatalf("listing wrote %v", w)
	}
}

func TestCredentialsSorted(t *testing.T) {
	h := newHarness(t)
	a, b := newAuthenticator(t), newAuthenticator(t)
	h.register("u1", a, "")
	h.clock.Advance(time.Minute)
	h.register("u1", b, "")
	list, err := h.svc.Credentials(h.ctx, "u1")
	if err != nil || len(list) != 2 || !list[0].CreatedAt.Before(list[1].CreatedAt) || string(list[0].ID) != string(a.CredentialID) {
		t.Fatalf("Credentials = %+v, %v", list, err)
	}
}

func TestRenameCredential(t *testing.T) {
	h := newHarness(t)
	a := newAuthenticator(t)
	h.register("u1", a, "")

	got, err := h.svc.RenameCredential(h.ctx, "u1", a.CredentialID, "  Work\x00 key\u0007 ")
	if err != nil || got.Name != "Work key" {
		t.Fatalf("rename = %+v, %v", got, err)
	}
	if rec := h.record(a.CredentialID); rec.Name != "Work key" {
		t.Fatalf("stored name = %q", rec.Name)
	}

	before := h.store.Writes()["RenameCredential"]
	if got, err := h.svc.RenameCredential(h.ctx, "u1", a.CredentialID, "Work key"); err != nil || got.Name != "Work key" {
		t.Fatalf("no-op rename = %+v, %v", got, err)
	}
	if after := h.store.Writes()["RenameCredential"]; after != before {
		t.Fatal("no-op rename wrote to the store")
	}

	for _, bad := range []string{"", "   ", "\n\t", strings.Repeat("é", 65)} {
		if _, err := h.svc.RenameCredential(h.ctx, "u1", a.CredentialID, bad); !errors.Is(err, ErrInvalidName) {
			t.Errorf("rename to %q = %v", bad, err)
		}
	}
	if got, err := h.svc.RenameCredential(h.ctx, "u1", a.CredentialID, strings.Repeat("é", 64)); err != nil || got.Name != strings.Repeat("é", 64) {
		t.Fatalf("64-rune rename = %v", err)
	}
}

func TestForeignCredentialIsNotFound(t *testing.T) {
	h := newHarness(t)
	a, b := newAuthenticator(t), newAuthenticator(t)
	h.register("u1", a, "")
	h.register("u2", b, "")
	if _, err := h.svc.RenameCredential(h.ctx, "u1", b.CredentialID, "mine now"); !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("rename foreign = %v", err)
	}
	if err := h.svc.DeleteCredential(h.ctx, "u1", b.CredentialID); !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("delete foreign = %v", err)
	}
	if err := h.svc.DeleteCredential(h.ctx, "u3", b.CredentialID); !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("delete by user without handle = %v", err)
	}
	if err := h.svc.DeleteCredential(h.ctx, "u1", []byte("nope")); !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("delete unknown = %v", err)
	}
	if rec := h.record(b.CredentialID); rec.Name != "" {
		t.Fatal("foreign credential was modified")
	}
}
