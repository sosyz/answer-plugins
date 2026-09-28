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

import { ApiError } from './api/client';

/** Reasons that have an `error.<reason>` translation. */
const KNOWN_REASONS = new Set([
  'bad_request',
  'unauthorized',
  'forbidden',
  'plugin_disabled',
  'not_configured',
  'state_required',
  'state_unverified',
  'session_invalid',
  'verification_failed',
  'clone_detected',
  'credential_exists',
  'credential_limit',
  'credential_not_found',
  'invalid_name',
  'internal_error',
  'network',
]);

/** Maps an API error to an i18n key (relative to the plugin frontend prefix). */
export function apiErrorKey(err: ApiError): string {
  if (KNOWN_REASONS.has(err.reason)) {
    return `error.${err.reason}`;
  }
  // Core middleware errors carry core reasons such as base.unauthorized_error.
  if (err.status === 401) {
    return 'error.unauthorized';
  }
  if (err.status === 403) {
    return 'error.forbidden';
  }
  return 'error.unknown';
}
