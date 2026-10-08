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

import {
  WebAuthnAbortService,
  browserSupportsWebAuthn,
  browserSupportsWebAuthnAutofill,
  startAuthentication,
  startRegistration,
} from '@simplewebauthn/browser';

import { ApiError } from './api/client';
import { apiErrorKey } from './errors';
import type {
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
} from './types';

export const supported = browserSupportsWebAuthn();

export const autofillSupported = (): Promise<boolean> =>
  supported ? browserSupportsWebAuthnAutofill() : Promise.resolve(false);

export const register = (options: PublicKeyCredentialCreationOptionsJSON) =>
  startRegistration({ optionsJSON: options });

export const authenticate = (
  options: PublicKeyCredentialRequestOptionsJSON,
  { autofill }: { autofill: boolean },
) =>
  startAuthentication({ optionsJSON: options, useBrowserAutofill: autofill });

/** Aborts the pending WebAuthn ceremony, if any. */
export const cancel = () => WebAuthnAbortService.cancelCeremony();

/**
 * Maps any error from a passkey flow to an i18n key, or null when it should
 * be ignored (the ceremony was aborted on purpose).
 */
export function webauthnErrorKey(err: unknown): string | null {
  if (err instanceof ApiError) {
    return apiErrorKey(err);
  }
  if (!(err instanceof Error)) {
    return 'error.unknown';
  }
  const code = (err as Error & { code?: string }).code;
  if (err.name === 'AbortError' || code === 'ERROR_CEREMONY_ABORTED') {
    return null;
  }
  if (err.name === 'NotAllowedError') {
    return 'webauthn.cancelled';
  }
  if (
    err.name === 'InvalidStateError' ||
    code === 'ERROR_AUTHENTICATOR_PREVIOUSLY_REGISTERED'
  ) {
    return 'webauthn.already_registered';
  }
  if (
    err.name === 'SecurityError' ||
    code === 'ERROR_INVALID_DOMAIN' ||
    code === 'ERROR_INVALID_RP_ID'
  ) {
    return 'webauthn.security';
  }
  return 'error.unknown';
}
