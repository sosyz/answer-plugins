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

import info from '../info.yaml';

/** This plugin's route, relative to the core UI base path. */
const PAGE_ROUTE: string = info.route;

/** Answer API path below the base path. */
const API_PATH = '/answer/api/v1';

/** Same key the Answer core uses to return to a page after signing in. */
const REDIRECT_PATH_STORAGE_KEY = '_a_rp_';

/**
 * Query parameters that carry a core OAuth state. They are never stored or
 * forwarded: a bind state is a bearer credential until it expires.
 */
const STATE_PARAMS = ['state', 'state_proof'];

/**
 * The core UI base path (ui.base_url), e.g. '' or '/community'.
 *
 * The core bakes ui.base_url and ui.api_url into its own bundle at build time
 * and injects nothing into index.html at runtime, and route plugins get no
 * props, so the base path is taken from this page's own URL: the core router
 * mounts plugin routes directly below its basename.
 */
export function basePath(): string {
  let path: string;
  try {
    path = decodeURIComponent(window.location.pathname).replace(/\/+$/, '');
  } catch {
    return '';
  }
  // The router matches the route case-insensitively and after decoding.
  if (!path.toLowerCase().endsWith(PAGE_ROUTE.toLowerCase())) {
    return '';
  }
  const base = path.slice(0, path.length - PAGE_ROUTE.length);
  // Plain path segments only: never '//' (protocol-relative) or characters
  // that would change the meaning of the API URL built from it.
  return /^(\/[^/?#\\]+)*$/.test(base) ? base : '';
}

/**
 * The Answer API base, e.g. '/community/answer/api/v1'. The core builds its
 * own connector URLs as Site URL + /answer/api/v1, i.e. connectors assume the
 * API lives below the same prefix as the UI; this does the same.
 */
export function apiBase(): string {
  return basePath() + API_PATH;
}

/** Core endpoint that redeems a passkey login token (server-built URL). */
const connectorRedirectPath = () => `${apiBase()}/connector/redirect/passkey`;

/** Core endpoint that starts a login-intent connector flow. */
const connectorLoginPath = () => `${apiBase()}/connector/login/passkey`;

/** The core sign-in page. */
export function loginURL(): string {
  return `${basePath()}/users/login`;
}

/** The core account settings page, which lists "My logins". */
export function accountSettingsURL(): string {
  return `${basePath()}/users/settings/account`;
}

/**
 * Navigates to a redirect_url returned by the plugin API. Only the core
 * connector redirect endpoint below this site's base path is accepted;
 * anything else throws. The origin is not pinned: the server builds the URL
 * from the Site URL, which may be another allowed origin of this site.
 */
export function safeRedirect(target: string): void {
  const url = new URL(target, window.location.href);
  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    throw new Error('unexpected redirect protocol');
  }
  if (url.pathname !== connectorRedirectPath()) {
    throw new Error('unexpected redirect path');
  }
  window.location.assign(url.href);
}

/**
 * Sends the user to the core sign-in page and returns to this page (without
 * any state parameter) afterwards.
 */
export function goToLogin(): void {
  const params = new URLSearchParams(window.location.search);
  STATE_PARAMS.forEach((p) => params.delete(p));
  const query = params.toString();
  try {
    // The core stores this path relative to its base path and navigates to
    // it through its router.
    localStorage.setItem(
      REDIRECT_PATH_STORAGE_KEY,
      PAGE_ROUTE + (query ? `?${query}` : ''),
    );
  } catch {
    // Storage unavailable: the core falls back to its default landing page.
  }
  window.location.assign(loginURL());
}

/** Starts a core login-intent flow, which comes back here with ?state=. */
export function startConnectorLogin(): void {
  window.location.replace(connectorLoginPath());
}

/** This page in credential management mode. */
export function manageURL(): string {
  return `${window.location.pathname}?mode=manage`;
}

/**
 * This page in account linking mode. `name` names the passkey if the user
 * creates a new one; it is omitted when empty.
 */
export function bindURL(name: string): string {
  const params = new URLSearchParams({ mode: 'bind' });
  if (name) {
    params.set('name', name);
  }
  return `${window.location.pathname}?${params.toString()}`;
}

/**
 * Removes the given query parameters from the address bar and the current
 * history entry, keeping the router's history state.
 */
export function dropQueryParams(names: string[]): void {
  const params = new URLSearchParams(window.location.search);
  if (!names.some((n) => params.has(n))) {
    return;
  }
  names.forEach((n) => params.delete(n));
  const query = params.toString();
  window.history.replaceState(
    window.history.state,
    '',
    window.location.pathname +
      (query ? `?${query}` : '') +
      window.location.hash,
  );
}
