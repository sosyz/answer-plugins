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

const API_BASE = '/answer/api/v1';

export interface BeginLoginResponse {
  session_id: string;
  options: PublicKeyCredentialRequestOptionsJSON;
}

export interface FinishLoginResponse {
  token: string;
}

export interface BeginRegisterResponse {
  session_id: string;
  options: PublicKeyCredentialCreationOptionsJSON;
}

export interface FinishRegisterResponse {
  success: boolean;
}

export interface CredentialInfo {
  id: string;
  name: string;
  created_at: string;
  last_used_at: string;
}

export interface ListCredentialsResponse {
  credentials: CredentialInfo[];
}

// PublicKeyCredentialCreationOptionsJSON matches the WebAuthn spec JSON serialization
export interface PublicKeyCredentialCreationOptionsJSON {
  publicKey: {
    rp: { name: string; id: string };
    user: { id: string; name: string; displayName: string };
    challenge: string;
    pubKeyCredParams: Array<{ type: string; alg: number }>;
    timeout?: number;
    excludeCredentials?: Array<{
      type: string;
      id: string;
      transports?: string[];
    }>;
    authenticatorSelection?: {
      authenticatorAttachment?: string;
      residentKey?: string;
      requireResidentKey?: boolean;
      userVerification?: string;
    };
    attestation?: string;
  };
}

// PublicKeyCredentialRequestOptionsJSON matches the WebAuthn spec JSON serialization
export interface PublicKeyCredentialRequestOptionsJSON {
  publicKey: {
    challenge: string;
    timeout?: number;
    rpId?: string;
    allowCredentials?: Array<{
      type: string;
      id: string;
      transports?: string[];
    }>;
    userVerification?: string;
  };
}

async function apiRequest<T>(
  url: string,
  options?: RequestInit,
): Promise<T> {
  const resp = await fetch(url, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...options?.headers,
    },
  });
  if (!resp.ok) {
    const body = await resp.json().catch(() => ({}));
    throw new Error(body.error || `Request failed with status ${resp.status}`);
  }
  return resp.json();
}

export async function beginLogin(): Promise<BeginLoginResponse> {
  return apiRequest<BeginLoginResponse>(`${API_BASE}/passkey/begin-login`, {
    method: 'POST',
  });
}

export async function finishLogin(
  sessionId: string,
  credential: Credential,
): Promise<FinishLoginResponse> {
  const pubKeyCred = credential as PublicKeyCredential;
  const response = pubKeyCred.response as AuthenticatorAssertionResponse;

  const body = {
    id: pubKeyCred.id,
    rawId: bufferToBase64URL(pubKeyCred.rawId),
    type: pubKeyCred.type,
    response: {
      authenticatorData: bufferToBase64URL(response.authenticatorData),
      clientDataJSON: bufferToBase64URL(response.clientDataJSON),
      signature: bufferToBase64URL(response.signature),
      userHandle: response.userHandle
        ? bufferToBase64URL(response.userHandle)
        : '',
    },
  };

  return apiRequest<FinishLoginResponse>(
    `${API_BASE}/passkey/finish-login?session_id=${encodeURIComponent(sessionId)}`,
    {
      method: 'POST',
      body: JSON.stringify(body),
    },
  );
}

export async function beginRegister(): Promise<BeginRegisterResponse> {
  return apiRequest<BeginRegisterResponse>(
    `${API_BASE}/passkey/begin-register`,
    {
      method: 'POST',
    },
  );
}

export async function finishRegister(
  sessionId: string,
  name: string,
  credential: Credential,
): Promise<FinishRegisterResponse> {
  const pubKeyCred = credential as PublicKeyCredential;
  const response = pubKeyCred.response as AuthenticatorAttestationResponse;

  const body = {
    id: pubKeyCred.id,
    rawId: bufferToBase64URL(pubKeyCred.rawId),
    type: pubKeyCred.type,
    response: {
      attestationObject: bufferToBase64URL(response.attestationObject),
      clientDataJSON: bufferToBase64URL(response.clientDataJSON),
    },
  };

  return apiRequest<FinishRegisterResponse>(
    `${API_BASE}/passkey/finish-register?session_id=${encodeURIComponent(sessionId)}&name=${encodeURIComponent(name)}`,
    {
      method: 'POST',
      body: JSON.stringify(body),
    },
  );
}

export async function listCredentials(): Promise<ListCredentialsResponse> {
  return apiRequest<ListCredentialsResponse>(
    `${API_BASE}/passkey/credentials`,
  );
}

export async function deleteCredential(id: string): Promise<void> {
  await apiRequest(`${API_BASE}/passkey/credentials/${encodeURIComponent(id)}`, {
    method: 'DELETE',
  });
}

// Utility: convert ArrayBuffer to base64url string
function bufferToBase64URL(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// Utility: convert base64url string to ArrayBuffer
export function base64URLToBuffer(base64url: string): ArrayBuffer {
  const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
  const padLen = (4 - (base64.length % 4)) % 4;
  const padded = base64 + '='.repeat(padLen);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}
