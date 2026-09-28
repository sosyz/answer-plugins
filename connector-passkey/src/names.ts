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

/** Longest passkey name the server accepts, in Unicode code points. */
export const MAX_NAME_LENGTH = 64;

/** Bidirectional embedding, override and isolate controls; the server drops them too. */
const BIDI_CONTROLS = /[\u202A-\u202E\u2066-\u2069]/g;

/**
 * Trims a user-entered passkey name and drops bidirectional controls, which
 * can make a name read differently from what it is. Returns null when it is
 * too long; an empty result means "let the server choose a default name".
 */
export function normalizeName(raw: string): string | null {
  const name = raw.replace(BIDI_CONTROLS, '').trim();
  return Array.from(name).length > MAX_NAME_LENGTH ? null : name;
}
