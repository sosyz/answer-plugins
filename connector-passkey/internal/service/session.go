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
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/segmentfault/pacman/log"
)

const (
	purposeLogin    = "login"
	purposeRegister = "register"
	purposeBind     = "bind"

	sessionAAD = "passkey_connector:ceremony:v1"
	// sessionKeyInfo derives the AES-256-GCM session key from the stored
	// secret (HKDF-SHA256), separately from the login state proof key.
	sessionKeyInfo = "passkey_connector:ceremony-session-key:v1"
	nonceSize      = 12
	maxSealedLen   = 16 << 10
)

// ceremonyState is sealed into the opaque session string returned by
// begin-* and opened again by finish-*. Nothing is stored server-side until a
// ceremony succeeds.
type ceremonyState struct {
	Purpose string               `json:"p"`
	UserID  string               `json:"u,omitempty"`
	Handle  string               `json:"h,omitempty"`
	State   string               `json:"s"`
	Expires int64                `json:"e"`
	Data    webauthn.SessionData `json:"d"`
}

func (s *Service) aead(ctx context.Context) (cipher.AEAD, error) {
	secret, err := s.store.CeremonyKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("passkey: ceremony key: %w", err)
	}
	key, err := hkdf.Key(sha256.New, secret, nil, sessionKeyInfo, 32)
	if err != nil {
		return nil, fmt.Errorf("passkey: session key: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("passkey: ceremony key: %w", err)
	}
	return cipher.NewGCM(block)
}

// seal encrypts st with AES-256-GCM: base64url(nonce || ciphertext).
func (s *Service) seal(ctx context.Context, st ceremonyState) (string, error) {
	plain, err := json.Marshal(st)
	if err != nil {
		return "", fmt.Errorf("passkey: encode session: %w", err)
	}
	gcm, err := s.aead(ctx)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, nonceSize, nonceSize+len(plain)+gcm.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("passkey: session nonce: %w", err)
	}
	sealed := gcm.Seal(nonce, nonce, plain, []byte(sessionAAD))
	return base64.RawURLEncoding.EncodeToString(sealed), nil
}

// open decrypts a session and checks its purpose and expiry. Every failure
// caused by the input is ErrSessionInvalid.
func (s *Service) open(ctx context.Context, sealed, purpose string) (ceremonyState, error) {
	if sealed == "" || len(sealed) > maxSealedLen {
		return ceremonyState{}, ErrSessionInvalid
	}
	raw, err := base64.RawURLEncoding.DecodeString(sealed)
	if err != nil || len(raw) < nonceSize {
		return ceremonyState{}, ErrSessionInvalid
	}
	gcm, err := s.aead(ctx)
	if err != nil {
		return ceremonyState{}, err
	}
	plain, err := gcm.Open(nil, raw[:nonceSize], raw[nonceSize:], []byte(sessionAAD))
	if err != nil {
		return ceremonyState{}, ErrSessionInvalid
	}
	var st ceremonyState
	if err := json.Unmarshal(plain, &st); err != nil {
		return ceremonyState{}, ErrSessionInvalid
	}
	if st.Purpose != purpose || st.Data.Challenge == "" || time.Unix(st.Expires, 0).Before(s.now()) {
		return ceremonyState{}, ErrSessionInvalid
	}
	return st, nil
}

func (s *Service) newState(purpose, userID, handle, state string, data *webauthn.SessionData) ceremonyState {
	return ceremonyState{
		Purpose: purpose,
		UserID:  userID,
		Handle:  handle,
		State:   state,
		Expires: s.now().Add(s.ceremonyTTL).Unix(),
		Data:    *data,
	}
}

// checkNotConsumed rejects a session whose challenge was already used. The
// finish-* calls check once early (cheap rejection of a replay) and again
// under the challenge lock right before saving.
func (s *Service) checkNotConsumed(ctx context.Context, challenge string) error {
	used, err := s.store.ChallengeConsumed(ctx, challenge)
	if err != nil {
		return fmt.Errorf("passkey: check challenge: %w", err)
	}
	if used {
		return ErrSessionInvalid
	}
	return nil
}

// saveFailed maps a failed SaveCeremonyResult. When the challenge is consumed
// by now, another finish call for the same session (on another instance, or
// a transaction that lost a unique-key race) won and this one is a replay:
// ErrSessionInvalid. Otherwise the store error is returned.
func (s *Service) saveFailed(ctx context.Context, challenge, what string, err error) error {
	if used, cerr := s.store.ChallengeConsumed(ctx, challenge); cerr == nil && used {
		log.Debugf("passkey: %s lost the race for its challenge: %v", what, err)
		return ErrSessionInvalid
	}
	return fmt.Errorf("passkey: %s: %w", what, err)
}

// consumedUntil is how long a used challenge is remembered: one ceremony
// lifetime past the session expiry, so that the purge of expired rows can
// never race the consumed check of a session that is still being opened.
func (s *Service) consumedUntil(st ceremonyState) time.Time {
	return time.Unix(st.Expires, 0).Add(s.ceremonyTTL)
}
