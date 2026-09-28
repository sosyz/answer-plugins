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

import type {
  AuthenticationResponseJSON,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
} from '@simplewebauthn/browser';

export type {
  AuthenticationResponseJSON,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
};

/** Response envelope shared by the Answer core and this plugin. */
export interface Envelope<T> {
  code: number;
  reason: string;
  msg: string;
  data: T;
}

/** A passkey as returned by the plugin API. `id` is the base64url credential ID. */
export interface CredentialView {
  id: string;
  name: string;
  created_at: string;
  last_used_at: string | null;
  backup_eligible: boolean;
  backup_state: boolean;
}

/** begin-* response for registration. `session` is opaque and single-use. */
export interface RegistrationCeremony {
  session: string;
  options: PublicKeyCredentialCreationOptionsJSON;
}

/** begin-* response for login and bind. `session` is opaque and single-use. */
export interface AssertionCeremony {
  session: string;
  options: PublicKeyCredentialRequestOptionsJSON;
}

export interface RedirectResult {
  redirect_url: string;
}

export interface RegisterBeginRequest {
  user_name: string;
  display_name?: string;
  state?: string;
}

export interface RegisterFinishRequest {
  session: string;
  name: string;
  credential: RegistrationResponseJSON;
}

export interface RegisterFinishResult {
  credential: CredentialView;
  /** Non-empty only when register/begin carried a core state. */
  redirect_url: string;
}

export interface CredentialList {
  credentials: CredentialView[];
}

export interface CredentialResult {
  credential: CredentialView;
}

/** The signed-in Answer user, from GET /user/info. */
export interface CurrentUser {
  username: string;
  display_name: string;
}

/** The passkey entry of GET /connector/user/info. */
export interface PasskeyConnector {
  binding: boolean;
  /** Absolute core URL; carries a fresh bind state when not bound. */
  link: string;
}

/**
 * Whether the account is linked to passkeys in the core ('error' when that
 * could not be determined).
 */
export type LinkState = 'loading' | 'error' | 'linked' | 'unlinked';
