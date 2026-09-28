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
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// loginProofInfo derives the login state proof key from the stored secret
// (HKDF-SHA256); the ceremony session key is derived from the same secret
// with sessionKeyInfo, so the two keys are independent.
const loginProofInfo = "passkey_connector:login-state-proof:v1"

// maxProofLen bounds the encoded proof accepted from the client
// (base64url of a 32-byte HMAC-SHA256 is 43 characters).
const maxProofLen = 64

// LoginStateProof returns a proof for a core login state that the plugin saw
// the core generate. BeginLogin accepts a state only together with its
// proof, so a state copied from a link, for example the bind state of another
// account, cannot be used for a sign-in ceremony.
func (s *Service) LoginStateProof(ctx context.Context, state string) (string, error) {
	mac, err := s.loginStateMAC(ctx, state)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(mac), nil
}

func (s *Service) checkLoginStateProof(ctx context.Context, state, proof string) error {
	if proof == "" || len(proof) > maxProofLen {
		return ErrStateUnverified
	}
	got, err := base64.RawURLEncoding.DecodeString(proof)
	if err != nil {
		return ErrStateUnverified
	}
	want, err := s.loginStateMAC(ctx, state)
	if err != nil {
		return err
	}
	if !hmac.Equal(got, want) {
		return ErrStateUnverified
	}
	return nil
}

func (s *Service) loginStateMAC(ctx context.Context, state string) ([]byte, error) {
	secret, err := s.store.CeremonyKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("passkey: ceremony key: %w", err)
	}
	key, err := hkdf.Key(sha256.New, secret, nil, loginProofInfo, sha256.Size)
	if err != nil {
		return nil, fmt.Errorf("passkey: login proof key: %w", err)
	}
	m := hmac.New(sha256.New, key)
	m.Write([]byte(state))
	return m.Sum(nil), nil
}
