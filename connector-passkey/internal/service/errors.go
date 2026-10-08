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

	"github.com/apache/answer-plugins/connector-passkey/internal/rp"
)

// Sentinel errors. The HTTP adapter maps them to status codes and reasons;
// any other error is internal.
var (
	// ErrNotConfigured is the rp sentinel itself, so errors.Is matches it
	// whichever package reported it.
	ErrNotConfigured      = rp.ErrNotConfigured
	ErrInvalidInput       = errors.New("passkey: invalid input")
	ErrStateRequired      = errors.New("passkey: state required")
	ErrStateUnverified    = errors.New("passkey: login state was not issued to this sign-in flow")
	ErrInvalidName        = errors.New("passkey: invalid name")
	ErrSessionInvalid     = errors.New("passkey: ceremony session invalid")
	ErrVerificationFailed = errors.New("passkey: verification failed")
	ErrCloneDetected      = errors.New("passkey: sign counter regression")
	ErrCredentialExists   = errors.New("passkey: credential already registered")
	ErrCredentialLimit    = errors.New("passkey: credential limit reached")
	ErrCredentialNotFound = errors.New("passkey: credential not found")
	ErrTokenInvalid       = errors.New("passkey: login token invalid")
)
