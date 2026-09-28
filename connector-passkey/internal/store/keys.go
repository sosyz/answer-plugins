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

package store

import (
	"crypto/sha256"
	"encoding/base64"
)

// KV groups. Every group and key stays within the 128-byte columns of the
// plugin_kv_storage table.
const (
	// GroupSecret holds KeyCeremony, the AES-256-GCM ceremony key.
	GroupSecret = "secret"
	KeyCeremony = "ceremony_key"
	// GroupUserHandle maps an Answer user ID to its WebAuthn user handle.
	GroupUserHandle = "user_handle"
	// GroupCredential maps CredentialKey(id) to a CredentialRecord. It is
	// also the global credential-ID uniqueness index.
	GroupCredential = "credential"
	// GroupMembershipPrefix + user handle lists the credential keys of a user.
	GroupMembershipPrefix = "user_credential:"
	// GroupConsumedChallenge maps a used challenge to its expiry.
	GroupConsumedChallenge = "consumed_challenge"
	// GroupLoginToken maps a token hash to a LoginToken.
	GroupLoginToken = "login_token"

	membershipValue = "1"
	groupPageSize   = 100
	// maxPurgePages bounds the pages of one group a single purge deletes.
	maxPurgePages = 10
)

// CredentialKey is the KV key of a credential: base64url(SHA-256(id)). Raw IDs
// can be up to 1023 bytes, so they are hashed to fit the key column.
func CredentialKey(id []byte) string {
	sum := sha256.Sum256(id)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// MembershipGroup is the group listing the credentials of a user handle.
func MembershipGroup(userHandle string) string {
	return GroupMembershipPrefix + userHandle
}
