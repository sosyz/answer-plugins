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

import { apiBase, goToLogin } from '../navigation';
import type { Envelope } from '../types';

/** Same key the Answer core uses to store the login token. */
const LOGGED_TOKEN_STORAGE_KEY = '_a_ltk_';

/** An API failure. `reason` is the envelope reason, or 'network'. */
export class ApiError extends Error {
  readonly status: number;
  readonly reason: string;

  constructor(status: number, reason: string) {
    super(reason);
    this.name = 'ApiError';
    this.status = status;
    this.reason = reason;
  }
}

/** Reads the core login token the same way core utils/storage.ts does. */
export function getToken(): string {
  try {
    const raw = localStorage.getItem(LOGGED_TOKEN_STORAGE_KEY);
    if (!raw) {
      return '';
    }
    try {
      const parsed: unknown = JSON.parse(raw);
      return typeof parsed === 'string' ? parsed : raw;
    } catch {
      return raw;
    }
  } catch {
    return '';
  }
}

export interface RequestOptions {
  /**
   * The endpoint requires a signed-in user. A 401 then sends the user to the
   * core sign-in page before the error is thrown.
   */
  authenticated?: boolean;
  /** Aborts the request; the returned promise then rejects with an AbortError. */
  signal?: AbortSignal;
}

export async function request<T>(
  method: 'GET' | 'POST' | 'PATCH' | 'DELETE',
  path: string,
  body?: unknown,
  { authenticated = false, signal }: RequestOptions = {},
): Promise<T> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };
  const token = getToken();
  if (token) {
    headers.Authorization = token;
  }

  let res: Response;
  let envelope: Envelope<T> | undefined;
  try {
    res = await fetch(apiBase() + path, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      signal,
    });
  } catch {
    throw abortReason(signal) ?? new ApiError(0, 'network');
  }
  try {
    envelope = (await res.json()) as Envelope<T>;
  } catch {
    envelope = undefined;
  }
  const aborted = abortReason(signal);
  if (aborted) {
    throw aborted;
  }

  if (res.status === 401 && authenticated) {
    goToLogin();
  }
  if (!envelope || typeof envelope !== 'object') {
    throw new ApiError(res.status, 'network');
  }
  if (!res.ok) {
    throw new ApiError(res.status, envelope.reason || 'unknown');
  }
  return envelope.data;
}

/** The error to throw for an aborted request, or null when not aborted. */
function abortReason(signal: AbortSignal | undefined): Error | null {
  if (!signal?.aborted) {
    return null;
  }
  const err = new Error('request aborted');
  err.name = 'AbortError';
  return err;
}
