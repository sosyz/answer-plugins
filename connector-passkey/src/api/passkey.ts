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

import { request } from './client';
import type {
  AssertionCeremony,
  AuthenticationResponseJSON,
  CredentialList,
  CredentialResult,
  RedirectResult,
  RegisterBeginRequest,
  RegisterFinishRequest,
  RegisterFinishResult,
  RegistrationCeremony,
} from '../types';

const auth = { authenticated: true };

const credentialPath = (id: string) =>
  `/passkey/credentials/${encodeURIComponent(id)}`;

// Unauthenticated: sign in with a discoverable passkey.

export const loginBegin = (
  state: string,
  proof: string,
  signal?: AbortSignal,
) =>
  request<AssertionCeremony>(
    'POST',
    '/passkey/login/begin',
    { state, state_proof: proof },
    { signal },
  );

export const loginFinish = (
  session: string,
  credential: AuthenticationResponseJSON,
  signal?: AbortSignal,
) =>
  request<RedirectResult>(
    'POST',
    '/passkey/login/finish',
    { session, credential },
    { signal },
  );

// Authenticated: create a passkey (with state when linking the account).

export const registerBegin = (req: RegisterBeginRequest) =>
  request<RegistrationCeremony>('POST', '/passkey/register/begin', req, auth);

export const registerFinish = (req: RegisterFinishRequest) =>
  request<RegisterFinishResult>('POST', '/passkey/register/finish', req, auth);

// Authenticated: link the account by proving an existing passkey.

export const bindBegin = (state: string) =>
  request<AssertionCeremony>('POST', '/passkey/bind/begin', { state }, auth);

export const bindFinish = (
  session: string,
  credential: AuthenticationResponseJSON,
) =>
  request<RedirectResult>(
    'POST',
    '/passkey/bind/finish',
    { session, credential },
    auth,
  );

// Authenticated: manage the caller's passkeys.

export const listCredentials = async () =>
  (
    await request<CredentialList>(
      'GET',
      '/passkey/credentials',
      undefined,
      auth,
    )
  ).credentials ?? [];

export const renameCredential = async (id: string, name: string) =>
  (await request<CredentialResult>('PATCH', credentialPath(id), { name }, auth))
    .credential;

export const deleteCredential = (id: string) =>
  request<null>('DELETE', credentialPath(id), undefined, auth);
