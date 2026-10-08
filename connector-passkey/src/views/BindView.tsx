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

import { useEffect, useRef, useState } from 'react';
import { Alert, Button, Spinner } from 'react-bootstrap';

import { bindStateOf, getPasskeyConnector } from '../api/core';
import {
  bindBegin,
  bindFinish,
  listCredentials,
  registerBegin,
  registerFinish,
} from '../api/passkey';
import StatusAlert, { Status } from '../components/StatusAlert';
import { normalizeName } from '../names';
import { manageURL, safeRedirect } from '../navigation';
import type { CredentialView, CurrentUser } from '../types';
import { useT } from '../useT';
import {
  authenticate,
  cancel,
  register,
  supported,
  webauthnErrorKey,
} from '../webauthn';

interface Props {
  user: CurrentUser;
  /** Name for a newly created passkey, from the page URL (may be empty). */
  name: string;
}

/**
 * Account linking for a signed-in user: create a new passkey, or prove one
 * they already have.
 *
 * The ?state= of this page's URL is deliberately ignored. Anyone can craft a
 * link carrying a bind state minted for their own account; using it would
 * bind the victim's passkey to the attacker's account. Each ceremony instead
 * asks the core for a bind state minted for the signed-in user.
 *
 * `name` comes from the manage view, which validates it; a name that is too
 * long (only possible with a hand-edited URL) is refused like there.
 */
function BindView({ user, name }: Props) {
  const { t } = useT();
  const label = normalizeName(name);
  const [credentials, setCredentials] = useState<CredentialView[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [redirecting, setRedirecting] = useState(false);
  const [status, setStatus] = useState<Status | null>(null);
  const [linked, setLinked] = useState(false);
  const alive = useRef(true);

  useEffect(() => {
    alive.current = true;
    getPasskeyConnector()
      .then((c) => alive.current && setLinked(c?.binding ?? false))
      .catch(() => undefined);
    listCredentials()
      .then((list) => {
        if (alive.current) {
          setCredentials(list);
        }
      })
      .catch((err) => {
        if (!alive.current) {
          return;
        }
        setCredentials([]);
        const key = webauthnErrorKey(err);
        if (key) {
          setStatus({ variant: 'danger', key });
        }
      });
    return () => {
      alive.current = false;
      cancel();
    };
  }, []);

  const run = async (ceremony: (state: string) => Promise<string>) => {
    setStatus(null);
    setBusy(true);
    try {
      // Fetched right before the ceremony: the bind state expires after
      // 5 minutes.
      const connector = await getPasskeyConnector();
      if (!alive.current) {
        return;
      }
      const state = connector ? bindStateOf(connector) : '';
      if (!state) {
        setBusy(false);
        if (connector?.binding) {
          setLinked(true);
        } else {
          setStatus({ variant: 'danger', key: 'error.state_required' });
        }
        return;
      }
      const redirectURL = await ceremony(state);
      if (!alive.current) {
        return;
      }
      setRedirecting(true);
      safeRedirect(redirectURL);
    } catch (err) {
      if (!alive.current) {
        return;
      }
      setBusy(false);
      setRedirecting(false);
      const key = webauthnErrorKey(err);
      if (key) {
        setStatus({ variant: 'danger', key });
      }
    }
  };

  const createPasskey = () => {
    if (label === null) {
      setStatus({ variant: 'danger', key: 'error.invalid_name' });
      return;
    }
    return run(async (state) => {
      const { session, options } = await registerBegin({
        user_name: user.username,
        display_name: user.display_name,
        state,
      });
      const credential = await register(options);
      const { redirect_url } = await registerFinish({
        session,
        name: label,
        credential,
      });
      return redirect_url;
    });
  };

  const proveExistingPasskey = () =>
    run(async (state) => {
      const { session, options } = await bindBegin(state);
      const credential = await authenticate(options, { autofill: false });
      const { redirect_url } = await bindFinish(session, credential);
      return redirect_url;
    });

  return (
    <>
      <h3 className="mb-3">{t('bind.title')}</h3>
      <p className="text-secondary text-break">
        {t('bind.description', {
          name: user.display_name || user.username,
        })}
      </p>

      <StatusAlert status={status} onClose={() => setStatus(null)} />

      {linked ? (
        <Alert variant="info">
          {t('bind.already_linked')}{' '}
          <a href={manageURL()}>{t('bind.manage_link')}</a>
        </Alert>
      ) : !supported ? (
        <Alert variant="warning">{t('webauthn.not_supported')}</Alert>
      ) : redirecting ? (
        <div role="status" className="d-flex align-items-center gap-2 py-2">
          <Spinner size="sm" aria-hidden="true" />
          <span>{t('bind.redirecting')}</span>
        </div>
      ) : credentials === null ? (
        <div role="status" className="d-flex align-items-center gap-2 py-2">
          <Spinner size="sm" aria-hidden="true" />
          <span>{t('common.loading')}</span>
        </div>
      ) : (
        <div className="d-grid gap-2">
          <Button
            variant="primary"
            size="lg"
            disabled={busy}
            aria-describedby={label ? 'passkey-bind-name' : undefined}
            onClick={createPasskey}
          >
            {t('bind.create_button')}
          </Button>
          {label && (
            <p
              id="passkey-bind-name"
              className="small text-secondary text-break mb-1"
            >
              {t('bind.new_name', { name: label })}
            </p>
          )}
          {credentials.length > 0 && (
            <Button
              variant="outline-primary"
              size="lg"
              disabled={busy}
              onClick={proveExistingPasskey}
            >
              {t('bind.use_existing_button')}
            </Button>
          )}
        </div>
      )}
    </>
  );
}

export default BindView;
