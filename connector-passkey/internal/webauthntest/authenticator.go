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

// Package webauthntest provides a software ES256 passkey authenticator for
// tests. It produces the W3C JSON a browser sends (RegistrationResponseJSON /
// AuthenticationResponseJSON, as returned by @simplewebauthn/browser) so the
// responses go through the real go-webauthn parsing and verification.
package webauthntest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
)

// Authenticator flags (WebAuthn §6.1).
const (
	flagUP = 0x01
	flagUV = 0x04
	flagBE = 0x08
	flagBS = 0x10
	flagAT = 0x40
)

// Authenticator is a discoverable-credential authenticator holding one P-256
// key. Fields may be changed between ceremonies.
type Authenticator struct {
	t   testing.TB
	key *ecdsa.PrivateKey
	// CredentialID is the credential ID (rawId).
	CredentialID []byte
	// UserHandle is captured from user.id at registration and returned in
	// assertions.
	UserHandle []byte
	// Counter is the signature counter reported by the next ceremony.
	Counter uint32
	// BackupEligible and BackupState set the BE and BS flags.
	BackupEligible bool
	BackupState    bool
	// Origin is written into clientDataJSON.
	Origin string
}

// New returns an authenticator with a random 32-byte credential ID, BE and
// BS set, for the given origin.
func New(t testing.TB, origin string) *Authenticator {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 32)
	if _, err := rand.Read(id); err != nil {
		t.Fatal(err)
	}
	return &Authenticator{t: t, key: key, CredentialID: id, BackupEligible: true, BackupState: true, Origin: origin}
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func (a *Authenticator) flags(extra byte) byte {
	f := byte(flagUP|flagUV) | extra
	if a.BackupEligible {
		f |= flagBE
	}
	if a.BackupState {
		f |= flagBS
	}
	return f
}

func (a *Authenticator) clientData(typ string, challenge protocol.URLEncodedBase64) []byte {
	return a.marshal(map[string]any{
		"type":        typ,
		"challenge":   challenge.String(),
		"origin":      a.Origin,
		"crossOrigin": false,
	})
}

func authDataPrefix(rpID string, flags byte, counter uint32) []byte {
	rpHash := sha256.Sum256([]byte(rpID))
	out := append([]byte{}, rpHash[:]...)
	out = append(out, flags)
	return binary.BigEndian.AppendUint32(out, counter)
}

// Create answers navigator.credentials.create() with a "none" attestation.
func (a *Authenticator) Create(opts protocol.PublicKeyCredentialCreationOptions) []byte {
	a.t.Helper()
	switch uid := opts.User.ID.(type) {
	case protocol.URLEncodedBase64:
		a.UserHandle = append([]byte{}, uid...)
	case string: // options decoded from the JSON sent to the browser
		b, err := base64.RawURLEncoding.DecodeString(uid)
		if err != nil {
			a.t.Fatalf("webauthntest: user.id %q is not base64url: %v", uid, err)
		}
		a.UserHandle = b
	default:
		a.t.Fatalf("webauthntest: unexpected user.id type %T", opts.User.ID)
	}

	cose, err := webauthncbor.Marshal(webauthncose.EC2PublicKeyData{
		PublicKeyData: webauthncose.PublicKeyData{KeyType: int64(webauthncose.EllipticKey), Algorithm: int64(webauthncose.AlgES256)},
		Curve:         1, // P-256
		XCoord:        a.key.PublicKey.X.FillBytes(make([]byte, 32)),
		YCoord:        a.key.PublicKey.Y.FillBytes(make([]byte, 32)),
	})
	if err != nil {
		a.t.Fatal(err)
	}
	authData := authDataPrefix(opts.RelyingParty.ID, a.flags(flagAT), a.Counter)
	authData = append(authData, make([]byte, 16)...) // AAGUID
	authData = binary.BigEndian.AppendUint16(authData, uint16(len(a.CredentialID)))
	authData = append(authData, a.CredentialID...)
	authData = append(authData, cose...)

	attObj, err := webauthncbor.Marshal(map[string]any{
		"fmt":      "none",
		"attStmt":  map[string]any{},
		"authData": authData,
	})
	if err != nil {
		a.t.Fatal(err)
	}
	return a.marshal(map[string]any{
		"id":    b64(a.CredentialID),
		"rawId": b64(a.CredentialID),
		"type":  "public-key",
		"response": map[string]any{
			"clientDataJSON":    b64(a.clientData("webauthn.create", opts.Challenge)),
			"attestationObject": b64(attObj),
			"transports":        []string{"internal", "hybrid"},
		},
		"authenticatorAttachment": "platform",
		"clientExtensionResults":  map[string]any{},
	})
}

// Get answers navigator.credentials.get() with the current Counter.
func (a *Authenticator) Get(opts protocol.PublicKeyCredentialRequestOptions) []byte {
	a.t.Helper()
	cd := a.clientData("webauthn.get", opts.Challenge)
	authData := authDataPrefix(opts.RelyingPartyID, a.flags(0), a.Counter)
	cdHash := sha256.Sum256(cd)
	digest := sha256.Sum256(append(append([]byte{}, authData...), cdHash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	if err != nil {
		a.t.Fatal(err)
	}
	return a.marshal(map[string]any{
		"id":    b64(a.CredentialID),
		"rawId": b64(a.CredentialID),
		"type":  "public-key",
		"response": map[string]any{
			"clientDataJSON":    b64(cd),
			"authenticatorData": b64(authData),
			"signature":         b64(sig),
			"userHandle":        b64(a.UserHandle),
		},
		"authenticatorAttachment": "platform",
		"clientExtensionResults":  map[string]any{},
	})
}

func (a *Authenticator) marshal(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		a.t.Fatal(err)
	}
	return b
}
