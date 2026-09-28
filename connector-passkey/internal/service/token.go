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
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"

	"github.com/apache/answer-plugins/connector-passkey/internal/store"
)

// mintToken returns a random one-time token and the hash it is stored under.
func mintToken() (raw, hash string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", fmt.Errorf("passkey: token: %w", err)
	}
	raw = base64.RawURLEncoding.EncodeToString(b)
	return raw, hashToken(raw), nil
}

func hashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func (s *Service) newLoginToken(handle, state string) (raw, hash string, tok *store.LoginToken, err error) {
	raw, hash, err = mintToken()
	if err != nil {
		return "", "", nil, err
	}
	tok = &store.LoginToken{ExternalID: handle, State: state, ExpiresAt: s.nowUTC().Add(tokenTTL)}
	return raw, hash, tok, nil
}

// receiverURL is the server-built core connector redirect URL carrying the
// token and state. The base comes from Config.ReceiverURL.
func (s *Service) receiverURL(token, state string) string {
	q := url.Values{"state": {state}, "token": {token}}
	return s.receiverBase() + "?" + q.Encode()
}

// RedeemLoginToken consumes a login token and returns the user handle it was
// minted for. The token must be unexpired and the state must equal the state
// sealed at minting time. Concurrent redemptions of one token are serialized
// in this process, so exactly one of them can succeed.
func (s *Service) RedeemLoginToken(ctx context.Context, token, state string) (string, error) {
	if token == "" || state == "" {
		return "", ErrTokenInvalid
	}
	hash := hashToken(token)
	unlock := s.tokenLocks.lock(hash)
	tok, err := s.store.TakeLoginToken(ctx, hash)
	unlock()
	if errors.Is(err, store.ErrNotFound) {
		return "", ErrTokenInvalid
	}
	if err != nil {
		return "", fmt.Errorf("passkey: redeem token: %w", err)
	}
	if tok.ExpiresAt.Before(s.now()) || tok.ExternalID == "" || tok.State == "" ||
		subtle.ConstantTimeCompare([]byte(tok.State), []byte(state)) != 1 {
		return "", ErrTokenInvalid
	}
	s.purge(ctx)
	return tok.ExternalID, nil
}
