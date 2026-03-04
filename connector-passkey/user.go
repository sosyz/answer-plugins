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
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// PasskeyUser implements the webauthn.User interface.
type PasskeyUser struct {
	ID          []byte
	DisplayName string
	Credentials []webauthn.Credential
}

func (u *PasskeyUser) WebAuthnID() []byte {
	return u.ID
}

func (u *PasskeyUser) WebAuthnName() string {
	return u.DisplayName
}

func (u *PasskeyUser) WebAuthnDisplayName() string {
	return u.DisplayName
}

func (u *PasskeyUser) WebAuthnCredentials() []webauthn.Credential {
	return u.Credentials
}

func (u *PasskeyUser) WebAuthnIcon() string {
	return ""
}

// storedToWebAuthnCredentials converts stored credentials to WebAuthn library credentials.
func storedToWebAuthnCredentials(stored []StoredCredential) []webauthn.Credential {
	creds := make([]webauthn.Credential, len(stored))
	for idx, s := range stored {
		transports := make([]protocol.AuthenticatorTransport, len(s.Transport))
		for j, t := range s.Transport {
			transports[j] = protocol.AuthenticatorTransport(t)
		}

		creds[idx] = webauthn.Credential{
			ID:              s.ID,
			PublicKey:       s.PublicKey,
			AttestationType: s.AttestationType,
			Transport:       transports,
			Flags: webauthn.CredentialFlags{
				UserPresent:    s.Flags.UserPresent,
				UserVerified:   s.Flags.UserVerified,
				BackupEligible: s.Flags.BackupEligible,
				BackupState:    s.Flags.BackupState,
			},
			Authenticator: webauthn.Authenticator{
				AAGUID:       s.Authenticator.AAGUID,
				SignCount:    s.Authenticator.SignCount,
				CloneWarning: s.Authenticator.CloneWarning,
				Attachment:   protocol.AuthenticatorAttachment(s.Authenticator.Attachment),
			},
		}
	}
	return creds
}

// webauthnToStoredCredential converts a WebAuthn library credential to our stored format.
func webauthnToStoredCredential(cred *webauthn.Credential, name string) StoredCredential {
	transports := make([]string, len(cred.Transport))
	for j, t := range cred.Transport {
		transports[j] = string(t)
	}

	return StoredCredential{
		ID:              cred.ID,
		PublicKey:       cred.PublicKey,
		AttestationType: cred.AttestationType,
		Transport:       transports,
		Flags: CredFlags{
			UserPresent:    cred.Flags.UserPresent,
			UserVerified:   cred.Flags.UserVerified,
			BackupEligible: cred.Flags.BackupEligible,
			BackupState:    cred.Flags.BackupState,
		},
		Authenticator: CredAuth{
			AAGUID:       cred.Authenticator.AAGUID,
			SignCount:    cred.Authenticator.SignCount,
			CloneWarning: cred.Authenticator.CloneWarning,
			Attachment:   string(cred.Authenticator.Attachment),
		},
		Name: name,
	}
}
