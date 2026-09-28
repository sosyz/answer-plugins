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

// Package service implements the passkey ceremonies and credential management
// on top of store.Store. It knows nothing about gin or the Answer plugin
// runtime: the relying party, the core receiver URL and the clock are
// injected.
package service

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/apache/answer-plugins/connector-passkey/internal/rp"
	"github.com/apache/answer-plugins/connector-passkey/internal/store"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/segmentfault/pacman/log"
)

const (
	// tokenTTL is the lifetime of a login token handed to the core receiver.
	tokenTTL              = 2 * time.Minute
	maxCredentialsPerUser = 20
	maxLabelRunes         = 64
	// maxStateBytes bounds the core OAuth state echoed through the session.
	maxStateBytes = 512
	// purgeInterval is the minimum time between two purges of expired rows
	// by one Service.
	purgeInterval = time.Minute
)

// Config wires a Service.
type Config struct {
	Store        store.Store
	RelyingParty func() (*webauthn.WebAuthn, error)
	// ReceiverURL returns the absolute (or, without a Site URL, relative)
	// URL of the core connector redirect endpoint of this plugin, without a
	// query.
	ReceiverURL func() string
	// CeremonyTTL is the lifetime of a sealed ceremony session. It must match
	// the webauthn timeouts of the relying party; it defaults to
	// rp.CeremonyTimeout.
	CeremonyTTL time.Duration
	// Now defaults to time.Now.
	Now func() time.Time
}

// Service runs the passkey ceremonies.
type Service struct {
	store        store.Store
	relyingParty func() (*webauthn.WebAuthn, error)
	receiverBase func() string
	ceremonyTTL  time.Duration
	now          func() time.Time

	// Single use of challenges and tokens is check-then-act on the KV store;
	// these locks make it atomic within this process (see stripedMutex for
	// the lock order).
	challengeLocks  *stripedMutex
	handleLocks     *stripedMutex
	credentialLocks *stripedMutex
	tokenLocks      *stripedMutex

	// lastPurge is the UnixNano time of the last purge (see purge).
	lastPurge atomic.Int64
}

// New returns a Service. Store, RelyingParty and ReceiverURL are required.
func New(cfg Config) *Service {
	s := &Service{
		store:           cfg.Store,
		relyingParty:    cfg.RelyingParty,
		receiverBase:    cfg.ReceiverURL,
		ceremonyTTL:     cfg.CeremonyTTL,
		now:             cfg.Now,
		challengeLocks:  newStripedMutex(),
		handleLocks:     newStripedMutex(),
		credentialLocks: newStripedMutex(),
		tokenLocks:      newStripedMutex(),
	}
	if s.now == nil {
		s.now = time.Now
	}
	if s.receiverBase == nil {
		s.receiverBase = func() string { return "" }
	}
	if s.ceremonyTTL <= 0 {
		s.ceremonyTTL = rp.CeremonyTimeout
	}
	return s
}

// Credential is the public view of a registered passkey.
type Credential struct {
	ID             []byte
	Name           string
	CreatedAt      time.Time
	LastUsedAt     time.Time
	BackupEligible bool
	BackupState    bool
}

// UserLabel carries the names an authenticator shows for the account. They
// are labels only and never used for identity.
type UserLabel struct {
	Name        string
	DisplayName string
}

// RegistrationCeremony is returned by BeginRegistration.
type RegistrationCeremony struct {
	Session string
	Options protocol.PublicKeyCredentialCreationOptions
}

// AssertionCeremony is returned by BeginLogin and BeginBind.
type AssertionCeremony struct {
	Session string
	Options protocol.PublicKeyCredentialRequestOptions
}

func (s *Service) rp() (*webauthn.WebAuthn, error) {
	if s.relyingParty == nil {
		return nil, ErrNotConfigured
	}
	w, err := s.relyingParty()
	if err != nil {
		if errors.Is(err, ErrNotConfigured) {
			return nil, err
		}
		return nil, fmt.Errorf("%w: %w", ErrNotConfigured, err)
	}
	return w, nil
}

func (s *Service) nowUTC() time.Time {
	return s.now().UTC()
}

func toView(rec store.CredentialRecord) Credential {
	return Credential{
		ID:             rec.Credential.ID,
		Name:           rec.Name,
		CreatedAt:      rec.CreatedAt,
		LastUsedAt:     rec.LastUsedAt,
		BackupEligible: rec.Credential.Flags.BackupEligible,
		BackupState:    rec.Credential.Flags.BackupState,
	}
}

func checkState(state string) error {
	if len(state) > maxStateBytes {
		return fmt.Errorf("%w: state too long", ErrInvalidInput)
	}
	return nil
}

func decodeHandle(handle string) ([]byte, error) {
	b, err := base64.RawURLEncoding.DecodeString(handle)
	if err != nil || len(b) == 0 {
		return nil, fmt.Errorf("passkey: malformed stored user handle")
	}
	return b, nil
}

func (s *Service) credentialsOf(ctx context.Context, handle string) ([]store.CredentialRecord, error) {
	recs, err := s.store.Credentials(ctx, handle)
	if err != nil {
		return nil, fmt.Errorf("passkey: list credentials: %w", err)
	}
	return recs, nil
}

// purge removes expired rows at most once per purgeInterval; failures are
// logged only. Expired rows are harmless (every reader checks expiry), so a
// skipped purge only delays their removal.
func (s *Service) purge(ctx context.Context) {
	now := s.nowUTC()
	last := s.lastPurge.Load()
	if last != 0 && now.Sub(time.Unix(0, last)) < purgeInterval {
		return
	}
	if !s.lastPurge.CompareAndSwap(last, now.UnixNano()) {
		return // another request is purging
	}
	if err := s.store.PurgeExpired(ctx, now); err != nil {
		log.Warnf("passkey: purge expired rows: %v", err)
	}
}

// verificationFailed logs the library error at debug level and returns
// ErrVerificationFailed.
func verificationFailed(ceremony string, err error) error {
	var perr *protocol.Error
	if errors.As(err, &perr) {
		log.Debugf("passkey: %s verification failed: %s (%s)", ceremony, perr.Details, perr.DevInfo)
	} else {
		log.Debugf("passkey: %s verification failed: %v", ceremony, err)
	}
	return ErrVerificationFailed
}
