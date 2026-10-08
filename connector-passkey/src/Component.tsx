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

import { ReactNode, useEffect, useMemo, useState } from 'react';
import { Alert, Spinner } from 'react-bootstrap';

import { getCurrentUser } from './api/core';
import {
  dropQueryParams,
  goToLogin,
  loginURL,
  startConnectorLogin,
} from './navigation';
import type { CurrentUser } from './types';
import { useT } from './useT';
import BindView from './views/BindView';
import LoginView from './views/LoginView';
import ManageView from './views/ManageView';
import { webauthnErrorKey } from './webauthn';

type Page =
  | { kind: 'loading' }
  | { kind: 'error'; key: string; withLoginLink: boolean }
  | { kind: 'navigating'; go: () => void }
  | { kind: 'login'; state: string; proof: string }
  | { kind: 'bind'; user: CurrentUser; name: string }
  | { kind: 'manage'; user: CurrentUser };

/**
 * Route /connector-passkey-auth. The mode is decided from the query string:
 *   ?mode=manage          manage passkeys (sign-in required)
 *   ?mode=bind[&name=N]   link a passkey (sign-in required); N names a new
 *                         passkey. Any state parameter is ignored.
 *   ?state=S&state_proof=P, signed out
 *                         sign in with a passkey (core login flow); P is the
 *                         server's proof that the core generated S for a
 *                         sign-in, so a state from a crafted link is refused
 *   ?state=S, signed in   link a passkey (S is ignored, see BindView)
 *   ?state=               incomplete link
 *   (nothing)             manage when signed in, else start a core login flow
 */
function resolvePage(params: URLSearchParams, user: CurrentUser | null): Page {
  const state = params.get('state') ?? '';
  const mode = params.get('mode');
  if (mode === 'manage') {
    return user
      ? { kind: 'manage', user }
      : { kind: 'navigating', go: goToLogin };
  }
  if (mode === 'bind') {
    return user
      ? { kind: 'bind', user, name: params.get('name') ?? '' }
      : { kind: 'navigating', go: goToLogin };
  }
  if (params.has('state') && !state) {
    return { kind: 'error', key: 'login.missing_state', withLoginLink: true };
  }
  if (state) {
    if (user) {
      return { kind: 'bind', user, name: '' };
    }
    const proof = params.get('state_proof') ?? '';
    return proof
      ? { kind: 'login', state, proof }
      : { kind: 'error', key: 'error.state_unverified', withLoginLink: true };
  }
  return user
    ? { kind: 'manage', user }
    : { kind: 'navigating', go: startConnectorLogin };
}

function Component() {
  const { t } = useT();
  const params = useMemo(() => new URLSearchParams(window.location.search), []);
  const [page, setPage] = useState<Page>({ kind: 'loading' });

  useEffect(() => {
    let active = true;
    getCurrentUser()
      .then((user) => {
        if (active) {
          setPage(resolvePage(params, user));
        }
      })
      .catch((err) => {
        if (active) {
          setPage({
            kind: 'error',
            key: webauthnErrorKey(err) ?? 'error.unknown',
            withLoginLink: false,
          });
        }
      });
    return () => {
      active = false;
    };
  }, [params]);

  useEffect(() => {
    if (page.kind === 'navigating') {
      page.go();
    }
    // The bind view never uses the URL state, but the core still honours it
    // until it expires: drop it from the address bar and history so it
    // cannot leak through a shared screen or URL. The name has been read.
    if (page.kind === 'bind') {
      dropQueryParams(['state', 'state_proof', 'name']);
    }
  }, [page]);

  let content: ReactNode;
  switch (page.kind) {
    case 'loading':
    case 'navigating':
      content = (
        <div role="status" className="d-flex align-items-center gap-2 py-3">
          <Spinner size="sm" aria-hidden="true" />
          <span>{t('common.loading')}</span>
        </div>
      );
      break;
    case 'error':
      content = (
        <>
          <Alert variant="danger">{t(page.key)}</Alert>
          {page.withLoginLink && (
            <a href={loginURL()}>{t('common.back_to_login')}</a>
          )}
        </>
      );
      break;
    case 'login':
      content = <LoginView state={page.state} proof={page.proof} />;
      break;
    case 'bind':
      content = <BindView user={page.user} name={page.name} />;
      break;
    case 'manage':
      content = <ManageView user={page.user} />;
      break;
  }

  return (
    <div className="mx-auto py-4 px-3" style={{ maxWidth: 480 }}>
      {content}
    </div>
  );
}

export default Component;
