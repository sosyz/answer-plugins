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

package passkey

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/apache/answer/plugin"
	"github.com/google/uuid"
	"github.com/segmentfault/pacman/log"
)

const (
	groupCredentials = "credentials"
	groupCredIndex   = "cred_index"
	groupUserMap     = "user_map"
	groupUserMapRev  = "user_map_rev"
	groupUserEmail   = "user_email"
	groupSession     = "session"
	groupToken       = "token"

	sessionTTL = 5 * time.Minute
	tokenTTL   = 2 * time.Minute
)

// StoredCredential represents a WebAuthn credential stored in KV.
type StoredCredential struct {
	ID              []byte    `json:"id"`
	PublicKey       []byte    `json:"public_key"`
	AttestationType string    `json:"attestation_type"`
	Transport       []string  `json:"transport"`
	Flags           CredFlags `json:"flags"`
	Authenticator   CredAuth  `json:"authenticator"`
	Name            string    `json:"name"`
	CreatedAt       time.Time `json:"created_at"`
	LastUsedAt      time.Time `json:"last_used_at"`
}

type CredFlags struct {
	UserPresent    bool `json:"user_present"`
	UserVerified   bool `json:"user_verified"`
	BackupEligible bool `json:"backup_eligible"`
	BackupState    bool `json:"backup_state"`
}

type CredAuth struct {
	AAGUID       []byte `json:"aaguid"`
	SignCount     uint32 `json:"sign_count"`
	CloneWarning bool   `json:"clone_warning"`
	Attachment   string `json:"attachment"`
}

// SessionData stores WebAuthn ceremony session data.
type SessionData struct {
	Data      json.RawMessage `json:"data"`
	Type      string          `json:"type"`
	CreatedAt time.Time       `json:"created_at"`
}

// TokenData stores one-time login token data.
type TokenData struct {
	UserExternalID string    `json:"user_external_id"`
	CreatedAt      time.Time `json:"created_at"`
}

// SetOperator implements plugin.KVStorage.
func (c *Connector) SetOperator(operator *plugin.KVOperator) {
	operator.Option(plugin.WithCacheTTL(-1)) // Disable cache for security-sensitive data
	c.kvOperator = operator
}

// getOrCreateExternalID gets or creates a mapping between Answer userID and external UUID.
func (c *Connector) getOrCreateExternalID(ctx context.Context, answerUserID string) (string, error) {
	kv := c.kvOperator

	// Try to get existing mapping
	externalID, err := kv.Get(ctx, plugin.KVParams{Group: groupUserMap, Key: answerUserID})
	if err == nil && externalID != "" {
		return externalID, nil
	}
	if err != nil && err != plugin.ErrKVKeyNotFound {
		return "", fmt.Errorf("failed to get user mapping: %w", err)
	}

	// Create new mapping
	externalID = uuid.New().String()
	err = kv.Tx(ctx, func(ctx context.Context, txKv *plugin.KVOperator) error {
		if err := txKv.Set(ctx, plugin.KVParams{Group: groupUserMap, Key: answerUserID, Value: externalID}); err != nil {
			return err
		}
		return txKv.Set(ctx, plugin.KVParams{Group: groupUserMapRev, Key: externalID, Value: answerUserID})
	})
	if err != nil {
		return "", fmt.Errorf("failed to create user mapping: %w", err)
	}
	return externalID, nil
}

// getAnswerUserID resolves an external ID back to an Answer user ID.
func (c *Connector) getAnswerUserID(ctx context.Context, externalID string) (string, error) {
	return c.kvOperator.Get(ctx, plugin.KVParams{Group: groupUserMapRev, Key: externalID})
}

// storeUserEmail stores the user's email associated with their external ID.
func (c *Connector) storeUserEmail(ctx context.Context, externalID string, email string) error {
	if email == "" {
		return nil
	}
	return c.kvOperator.Set(ctx, plugin.KVParams{Group: groupUserEmail, Key: externalID, Value: email})
}

// getUserEmail retrieves the stored email for an external ID.
func (c *Connector) getUserEmail(ctx context.Context, externalID string) (string, error) {
	email, err := c.kvOperator.Get(ctx, plugin.KVParams{Group: groupUserEmail, Key: externalID})
	if err == plugin.ErrKVKeyNotFound {
		return "", nil
	}
	return email, err
}

// getCredentials loads all credentials for a user.
func (c *Connector) getCredentials(ctx context.Context, userExternalID string) ([]StoredCredential, error) {
	raw, err := c.kvOperator.Get(ctx, plugin.KVParams{Group: groupCredentials, Key: userExternalID})
	if err == plugin.ErrKVKeyNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	var creds []StoredCredential
	if err := json.Unmarshal([]byte(raw), &creds); err != nil {
		return nil, fmt.Errorf("failed to unmarshal credentials: %w", err)
	}
	return creds, nil
}

// saveCredentials stores credentials and updates the reverse index atomically.
func (c *Connector) saveCredentials(ctx context.Context, userExternalID string, creds []StoredCredential) error {
	data, err := json.Marshal(creds)
	if err != nil {
		return fmt.Errorf("failed to marshal credentials: %w", err)
	}

	return c.kvOperator.Tx(ctx, func(ctx context.Context, txKv *plugin.KVOperator) error {
		if err := txKv.Set(ctx, plugin.KVParams{Group: groupCredentials, Key: userExternalID, Value: string(data)}); err != nil {
			return err
		}

		// Update reverse index for all credentials
		for _, cred := range creds {
			credIDKey := base64.RawURLEncoding.EncodeToString(cred.ID)
			if err := txKv.Set(ctx, plugin.KVParams{Group: groupCredIndex, Key: credIDKey, Value: userExternalID}); err != nil {
				return err
			}
		}
		return nil
	})
}

// addCredential adds a credential to a user's credential list.
func (c *Connector) addCredential(ctx context.Context, userExternalID string, cred StoredCredential) error {
	existing, err := c.getCredentials(ctx, userExternalID)
	if err != nil {
		return err
	}
	existing = append(existing, cred)
	return c.saveCredentials(ctx, userExternalID, existing)
}

// deleteCredential removes a credential by its ID.
func (c *Connector) deleteCredential(ctx context.Context, userExternalID string, credentialID []byte) error {
	existing, err := c.getCredentials(ctx, userExternalID)
	if err != nil {
		return err
	}

	credIDKey := base64.RawURLEncoding.EncodeToString(credentialID)
	filtered := make([]StoredCredential, 0, len(existing))
	for _, cred := range existing {
		if base64.RawURLEncoding.EncodeToString(cred.ID) != credIDKey {
			filtered = append(filtered, cred)
		}
	}

	return c.kvOperator.Tx(ctx, func(ctx context.Context, txKv *plugin.KVOperator) error {
		data, err := json.Marshal(filtered)
		if err != nil {
			return err
		}
		if err := txKv.Set(ctx, plugin.KVParams{Group: groupCredentials, Key: userExternalID, Value: string(data)}); err != nil {
			return err
		}
		// Remove from reverse index
		return txKv.Del(ctx, plugin.KVParams{Group: groupCredIndex, Key: credIDKey})
	})
}

// updateCredentialUsage updates the last-used timestamp and sign count for a credential.
func (c *Connector) updateCredentialUsage(ctx context.Context, userExternalID string, credentialID []byte, signCount uint32) error {
	existing, err := c.getCredentials(ctx, userExternalID)
	if err != nil {
		return err
	}

	credIDKey := base64.RawURLEncoding.EncodeToString(credentialID)
	for idx := range existing {
		if base64.RawURLEncoding.EncodeToString(existing[idx].ID) == credIDKey {
			existing[idx].LastUsedAt = time.Now()
			existing[idx].Authenticator.SignCount = signCount
			break
		}
	}

	data, err := json.Marshal(existing)
	if err != nil {
		return err
	}
	return c.kvOperator.Set(ctx, plugin.KVParams{Group: groupCredentials, Key: userExternalID, Value: string(data)})
}

// lookupUserByCredentialID finds the user external ID that owns a given credential.
func (c *Connector) lookupUserByCredentialID(ctx context.Context, credentialID []byte) (string, error) {
	credIDKey := base64.RawURLEncoding.EncodeToString(credentialID)
	return c.kvOperator.Get(ctx, plugin.KVParams{Group: groupCredIndex, Key: credIDKey})
}

// saveSession stores session data in KV with a generated session ID.
func (c *Connector) saveSession(ctx context.Context, sessionType string, data json.RawMessage) (string, error) {
	sessionID := uuid.New().String()
	sd := SessionData{
		Data:      data,
		Type:      sessionType,
		CreatedAt: time.Now(),
	}
	raw, err := json.Marshal(sd)
	if err != nil {
		return "", err
	}
	err = c.kvOperator.Set(ctx, plugin.KVParams{Group: groupSession, Key: sessionID, Value: string(raw)})
	if err != nil {
		return "", err
	}
	return sessionID, nil
}

// consumeSession retrieves and deletes a session (single-use).
func (c *Connector) consumeSession(ctx context.Context, sessionID string, expectedType string) (*SessionData, error) {
	raw, err := c.kvOperator.Get(ctx, plugin.KVParams{Group: groupSession, Key: sessionID})
	if err != nil {
		return nil, fmt.Errorf("session not found: %w", err)
	}

	// Delete immediately (single-use)
	if err := c.kvOperator.Del(ctx, plugin.KVParams{Group: groupSession, Key: sessionID}); err != nil {
		log.Warnf("failed to delete consumed session %s: %v", sessionID, err)
	}

	var sd SessionData
	if err := json.Unmarshal([]byte(raw), &sd); err != nil {
		return nil, fmt.Errorf("failed to unmarshal session: %w", err)
	}

	if sd.Type != expectedType {
		return nil, fmt.Errorf("session type mismatch: expected %s, got %s", expectedType, sd.Type)
	}

	if time.Since(sd.CreatedAt) > sessionTTL {
		return nil, fmt.Errorf("session expired")
	}

	return &sd, nil
}

// createToken creates a one-time login token.
func (c *Connector) createToken(ctx context.Context, userExternalID string) (string, error) {
	token := uuid.New().String()
	td := TokenData{
		UserExternalID: userExternalID,
		CreatedAt:      time.Now(),
	}
	raw, err := json.Marshal(td)
	if err != nil {
		return "", err
	}
	err = c.kvOperator.Set(ctx, plugin.KVParams{Group: groupToken, Key: token, Value: string(raw)})
	if err != nil {
		return "", err
	}
	return token, nil
}

// consumeToken retrieves and deletes a login token (single-use).
func (c *Connector) consumeToken(ctx context.Context, token string) (*TokenData, error) {
	raw, err := c.kvOperator.Get(ctx, plugin.KVParams{Group: groupToken, Key: token})
	if err != nil {
		return nil, fmt.Errorf("token not found: %w", err)
	}

	// Delete immediately (single-use)
	if err := c.kvOperator.Del(ctx, plugin.KVParams{Group: groupToken, Key: token}); err != nil {
		log.Warnf("failed to delete consumed token %s: %v", token, err)
	}

	var td TokenData
	if err := json.Unmarshal([]byte(raw), &td); err != nil {
		return nil, fmt.Errorf("failed to unmarshal token: %w", err)
	}

	if time.Since(td.CreatedAt) > tokenTTL {
		return nil, fmt.Errorf("token expired")
	}

	return &td, nil
}


