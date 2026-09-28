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

import { useCallback, useEffect, useRef, useState } from 'react';
import { Alert, Button, Form, Spinner } from 'react-bootstrap';

import { loginBegin, loginFinish } from '../api/passkey';
import StatusAlert, { Status } from '../components/StatusAlert';
import { loginURL, safeRedirect } from '../navigation';
import { useT } from '../useT';
import {
  authenticate,
  autofillSupported,
  cancel,
  supported,
  webauthnErrorKey,
} from '../webauthn';

/**
 * Assumed ceremony timeout when the server options carry none. The server
 * currently sends 5 minutes, the lifetime of the sealed session.
 */
const FALLBACK_TIMEOUT_MS = 5 * 60 * 1000;

/** Autofill is re-armed this long before its ceremony times out. */
const REARM_MARGIN_MS = 20 * 1000;

/**
 * Delay before replacing an autofill request whose options allow `timeout`
 * milliseconds, so that a passkey picked from autofill never meets an expired
 * session.
 */
function rearmDelay(timeout: number | undefined): number {
  const ms = timeout && timeout > 0 ? timeout : FALLBACK_TIMEOUT_MS;
  return Math.max(ms - REARM_MARGIN_MS, ms / 2);
}

interface Props {
  /** Core OAuth state from the page URL (non-empty). */
  state: string;
  /** Server proof that the core generated state for a sign-in. */
  proof: string;
}

/**
 * Sign-in with a discoverable passkey, either from the browser's autofill
 * (conditional mediation) or from the explicit button (modal).
 *
 * The same core state is reused for every attempt. It is not restarted when
 * the core's copy expires: the core then still completes a sign-in (it only
 * needs the state for account linking), and restarting would risk a loop.
 */
function LoginView({ state, proof }: Props) {
  const { t } = useT();
  const [autofill, setAutofill] = useState(false);
  const [busy, setBusy] = useState(false);
  const [redirecting, setRedirecting] = useState(false);
  const [status, setStatus] = useState<Status | null>(null);

  // Each flow gets an id; a flow whose id is no longer current was superseded
  // (another flow started or the view unmounted) and must stop quietly. Its
  // pending requests are aborted and its re-arm timer cleared.
  const flow = useRef(0);
  const requests = useRef<AbortController | null>(null);
  const rearmTimer = useRef<number | undefined>(undefined);

  const clearRearm = useCallback(() => {
    window.clearTimeout(rearmTimer.current);
    rearmTimer.current = undefined;
  }, []);

  /** Ends the current flow. Returns the id of the next one. */
  const endFlow = useCallback(() => {
    requests.current?.abort();
    requests.current = null;
    clearRearm();
    return ++flow.current;
  }, [clearRearm]);

  const beginFlow = useCallback(() => {
    const id = endFlow();
    requests.current = new AbortController();
    return { id, signal: requests.current.signal };
  }, [endFlow]);

  const finish = useCallback(
    async (
      id: number,
      session: string,
      credential: Parameters<typeof loginFinish>[1],
      signal: AbortSignal,
    ) => {
      const { redirect_url } = await loginFinish(session, credential, signal);
      if (flow.current !== id) {
        return;
      }
      setRedirecting(true);
      safeRedirect(redirect_url);
    },
    [],
  );

  const startAutofill = useCallback(async () => {
    const { id, signal } = beginFlow();
    let picked = false;
    try {
      const { session, options } = await loginBegin(state, proof, signal);
      if (flow.current !== id) {
        return;
      }
      // The sealed session expires with the ceremony: replace the request
      // with a fresh one shortly before that.
      rearmTimer.current = window.setTimeout(() => {
        if (flow.current === id) {
          void startAutofill();
        }
      }, rearmDelay(options.timeout));
      const credential = await authenticate(options, { autofill: true });
      if (flow.current !== id) {
        return;
      }
      clearRearm();
      picked = true;
      setStatus(null);
      setBusy(true);
      await finish(id, session, credential, signal);
    } catch (err) {
      if (flow.current !== id) {
        return;
      }
      clearRearm();
      setBusy(false);
      setRedirecting(false);
      const key = webauthnErrorKey(err);
      // Dismissing the autofill prompt is not an error worth showing.
      if (key && key !== 'webauthn.cancelled') {
        setStatus({ variant: 'danger', key });
      }
      // The picked passkey was refused (expired session, failed
      // verification, ...): offer autofill again. Not after a failure to
      // begin, which would recur in a loop, nor after the browser rejected
      // the conditional request, which some browsers do immediately.
      if (picked) {
        void startAutofill();
      }
    }
  }, [state, proof, beginFlow, clearRearm, finish]);

  const startModal = async () => {
    // Stop the autofill request first, so that a passkey picked from it
    // meanwhile cannot be dropped silently.
    cancel();
    const { id, signal } = beginFlow();
    setStatus(null);
    setBusy(true);
    let begun = false;
    try {
      const { session, options } = await loginBegin(state, proof, signal);
      if (flow.current !== id) {
        return;
      }
      begun = true;
      const credential = await authenticate(options, { autofill: false });
      if (flow.current !== id) {
        return;
      }
      await finish(id, session, credential, signal);
    } catch (err) {
      if (flow.current !== id) {
        return;
      }
      setBusy(false);
      setRedirecting(false);
      const key = webauthnErrorKey(err);
      if (key) {
        setStatus({ variant: 'danger', key });
      }
      // The modal request replaced the autofill request; re-arm it, unless
      // the ceremony could not even begin (autofill would fail the same way).
      if (autofill && begun) {
        void startAutofill();
      }
    }
  };

  useEffect(() => {
    let active = true;
    autofillSupported()
      .then((ok) => {
        if (active && ok) {
          setAutofill(true);
        }
      })
      .catch(() => undefined);
    return () => {
      active = false;
    };
  }, []);

  // The autofill request needs the webauthn input in the DOM, so it starts
  // after the render that shows it.
  useEffect(() => {
    if (autofill) {
      void startAutofill();
    }
  }, [autofill, startAutofill]);

  useEffect(
    () => () => {
      endFlow();
      cancel();
    },
    [endFlow],
  );

  return (
    <>
      <h3 className="mb-3">{t('login.title')}</h3>
      <p className="text-secondary">{t('login.description')}</p>

      <StatusAlert status={status} onClose={() => setStatus(null)} />

      {!supported ? (
        <Alert variant="warning">{t('webauthn.not_supported')}</Alert>
      ) : redirecting ? (
        <div role="status" className="d-flex align-items-center gap-2 py-2">
          <Spinner size="sm" aria-hidden="true" />
          <span>{t('login.redirecting')}</span>
        </div>
      ) : (
        <>
          {autofill && (
            <Form.Group className="mb-3" controlId="passkey-autofill">
              <Form.Label visuallyHidden>
                {t('login.autofill_label')}
              </Form.Label>
              <Form.Control
                type="text"
                name="username"
                autoComplete="username webauthn"
                aria-label={t('login.autofill_label')}
                placeholder={t('login.autofill_placeholder')}
                disabled={busy}
              />
            </Form.Group>
          )}
          <div className="d-grid">
            <Button
              variant="primary"
              size="lg"
              disabled={busy}
              onClick={startModal}
            >
              {busy && (
                <Spinner size="sm" className="me-2" aria-hidden="true" />
              )}
              {t('login.button')}
            </Button>
          </div>
        </>
      )}

      <p className="small text-secondary mt-4 mb-2">
        {t('login.no_passkey_hint')}
      </p>
      <a href={loginURL()}>{t('common.back_to_login')}</a>
    </>
  );
}

export default LoginView;
