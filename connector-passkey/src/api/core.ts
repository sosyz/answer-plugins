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

import { getToken, request } from './client';
import type { CurrentUser, PasskeyConnector } from '../types';

interface UserInfo {
  username?: string;
  display_name?: string;
}

interface ConnectorUserInfo {
  name: string;
  icon: string;
  link: string;
  binding: boolean;
  external_id: string;
}

const PASSKEY_LOGIN_PATH_SUFFIX = '/connector/login/passkey';

/** The signed-in user, or null when there is no valid login token. */
export async function getCurrentUser(): Promise<CurrentUser | null> {
  if (!getToken()) {
    return null;
  }
  const data = await request<UserInfo | null>('GET', '/user/info');
  if (!data || !data.username) {
    return null;
  }
  return {
    username: data.username,
    display_name: data.display_name ?? '',
  };
}

function isPasskeyLink(link: string): boolean {
  try {
    const url = new URL(link, window.location.href);
    return (
      (url.protocol === 'https:' || url.protocol === 'http:') &&
      url.pathname.endsWith(PASSKEY_LOGIN_PATH_SUFFIX)
    );
  } catch {
    return false;
  }
}

/**
 * The passkey connector entry for the signed-in user. When not bound, `link`
 * carries a bind state that expires after 5 minutes, so call this right
 * before navigating to it.
 */
export async function getPasskeyConnector(): Promise<PasskeyConnector | null> {
  const list = await request<ConnectorUserInfo[] | null>(
    'GET',
    '/connector/user/info',
    undefined,
    { authenticated: true },
  );
  const entry = (list ?? []).find((c) => isPasskeyLink(c.link));
  return entry ? { binding: entry.binding, link: entry.link } : null;
}

/**
 * The bind state the core minted for the signed-in user, taken from an
 * unbound connector link; '' when the account is already linked.
 */
export function bindStateOf(connector: PasskeyConnector): string {
  if (connector.binding) {
    return '';
  }
  try {
    return (
      new URL(connector.link, window.location.href).searchParams.get('state') ??
      ''
    );
  } catch {
    return '';
  }
}
