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
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/apache/answer-plugins/connector-passkey/internal/rp"
)

func TestSessionSealOpen(t *testing.T) {
	h := newHarness(t)
	cer, err := h.svc.BeginLogin(h.ctx, "st", h.proof("st"))
	if err != nil {
		t.Fatal(err)
	}
	st := mustOpen(t, h, cer.Session, purposeLogin)
	if st.State != "st" || st.Data.Challenge != cer.Options.Challenge.String() || st.Expires != h.clock.Now().Add(rp.CeremonyTimeout).Unix() {
		t.Fatalf("opened state %+v", st)
	}
	if _, err := h.svc.open(h.ctx, cer.Session, purposeRegister); !errors.Is(err, ErrSessionInvalid) {
		t.Fatalf("wrong purpose = %v", err)
	}
}

func TestSessionTampered(t *testing.T) {
	h := newHarness(t)
	a := newAuthenticator(t)
	h.register("u1", a, "")
	cer, err := h.svc.BeginLogin(h.ctx, "st", h.proof("st"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(cer.Session)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)/2] ^= 0x01
	tampered := base64.RawURLEncoding.EncodeToString(raw)
	for _, s := range []string{tampered, "", "not base64 !", "c2hvcnQ", cer.Session[:len(cer.Session)-4]} {
		if _, err := h.svc.FinishLogin(h.ctx, s, a.Get(cer.Options)); !errors.Is(err, ErrSessionInvalid) {
			t.Errorf("FinishLogin(%.20q) = %v", s, err)
		}
	}
}

func TestSessionExpired(t *testing.T) {
	h := newHarness(t)
	a := newAuthenticator(t)
	h.register("u1", a, "")
	cer, err := h.svc.BeginLogin(h.ctx, "st", h.proof("st"))
	if err != nil {
		t.Fatal(err)
	}
	reg, err := h.svc.BeginRegistration(h.ctx, "u1", label("u1"), "")
	if err != nil {
		t.Fatal(err)
	}
	h.clock.Advance(6 * time.Minute)
	if _, err := h.svc.FinishLogin(h.ctx, cer.Session, a.Get(cer.Options)); !errors.Is(err, ErrSessionInvalid) {
		t.Fatalf("expired login = %v", err)
	}
	if _, _, err := h.svc.FinishRegistration(h.ctx, "u1", reg.Session, "", newAuthenticator(t).Create(reg.Options)); !errors.Is(err, ErrSessionInvalid) {
		t.Fatalf("expired registration = %v", err)
	}
}

func TestSessionFromAnotherKey(t *testing.T) {
	h1, h2 := newHarness(t), newHarness(t)
	cer, err := h1.svc.BeginLogin(h1.ctx, "st", h1.proof("st"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h2.svc.open(h2.ctx, cer.Session, purposeLogin); !errors.Is(err, ErrSessionInvalid) {
		t.Fatalf("session sealed with another key = %v", err)
	}
}
