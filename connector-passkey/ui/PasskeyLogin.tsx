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

import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Button, Alert, Spinner } from 'react-bootstrap';

import { beginLogin, finishLogin, base64URLToBuffer } from './api';

function getSearchParam(key: string): string {
  return new URLSearchParams(location.search).get(key) || '';
}

function PasskeyLogin() {
  const { t } = useTranslation('plugin', {
    keyPrefix: 'passkey_connector.frontend',
  });

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const receiverURL = getSearchParam('receiver');

  const handleLogin = async () => {
    setError('');
    setLoading(true);

    try {
      // Check browser support
      if (!window.PublicKeyCredential) {
        setError(t('error_not_supported'));
        setLoading(false);
        return;
      }

      // Step 1: Begin login - get challenge from server
      const { session_id, options } = await beginLogin();

      // Step 2: Convert options for the browser API
      const publicKeyOptions = options.publicKey;
      const credentialRequestOptions: CredentialRequestOptions = {
        publicKey: {
          challenge: base64URLToBuffer(publicKeyOptions.challenge),
          timeout: publicKeyOptions.timeout,
          rpId: publicKeyOptions.rpId,
          userVerification:
            (publicKeyOptions.userVerification as UserVerificationRequirement) ||
            'required',
          allowCredentials: (publicKeyOptions.allowCredentials || []).map(
            (c) => ({
              type: c.type as PublicKeyCredentialType,
              id: base64URLToBuffer(c.id),
              transports: (c.transports || []) as AuthenticatorTransport[],
            }),
          ),
        },
      };

      // Step 3: Call WebAuthn API
      const credential = await navigator.credentials.get(
        credentialRequestOptions,
      );
      if (!credential) {
        setError(t('login_cancelled'));
        setLoading(false);
        return;
      }

      // Step 4: Send assertion to server
      const { token } = await finishLogin(session_id, credential);

      // Step 5: Redirect to receiver with token
      if (receiverURL) {
        const separator = receiverURL.includes('?') ? '&' : '?';
        location.href = `${receiverURL}${separator}token=${encodeURIComponent(token)}`;
      }
    } catch (err) {
      const message =
        err instanceof Error ? err.message : t('error_generic');
      if (
        message.includes('NotAllowedError') ||
        message.includes('AbortError')
      ) {
        setError(t('login_cancelled'));
      } else {
        setError(t('login_error').replace('${ERROR}', message));
      }
      setLoading(false);
    }
  };

  return (
    <div>
      <h3 className="mb-3">{t('login_title')}</h3>
      <p className="text-secondary">{t('login_description')}</p>

      {error && (
        <Alert variant="danger" onClose={() => setError('')} dismissible>
          {error}
        </Alert>
      )}

      <div className="d-grid gap-2">
        <Button
          variant="primary"
          size="lg"
          onClick={handleLogin}
          disabled={loading}
        >
          {loading ? (
            <>
              <Spinner size="sm" className="me-2" />
              {t('loading')}
            </>
          ) : (
            t('login_button')
          )}
        </Button>
      </div>
    </div>
  );
}

export default PasskeyLogin;
