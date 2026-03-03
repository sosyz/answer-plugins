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

import { useState, useEffect, useCallback, useRef } from 'react';
import { useTranslation } from 'react-i18next';
import {
  Button,
  Alert,
  Spinner,
  ListGroup,
  Form,
  Modal,
} from 'react-bootstrap';

import {
  beginRegister,
  finishRegister,
  beginLogin,
  finishLogin,
  listCredentials,
  deleteCredential,
  base64URLToBuffer,
  CredentialInfo,
} from './api';

function PasskeyManage() {
  const { t } = useTranslation('plugin', {
    keyPrefix: 'passkey_connector.frontend',
  });

  const [credentials, setCredentials] = useState<CredentialInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [registering, setRegistering] = useState(false);
  const [newName, setNewName] = useState('');
  const [showNameInput, setShowNameInput] = useState(false);
  const [deleteTarget, setDeleteTarget] = useState<CredentialInfo | null>(null);
  const [testing, setTesting] = useState(false);
  const [verifiedCredId, setVerifiedCredId] = useState<string | null>(null);
  const verifiedTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const loadCredentials = useCallback(async () => {
    try {
      setLoading(true);
      const resp = await listCredentials();
      setCredentials(resp.credentials || []);
    } catch (err) {
      setError(err instanceof Error ? err.message : t('error_generic'));
    } finally {
      setLoading(false);
    }
  }, [t]);

  useEffect(() => {
    loadCredentials();
  }, [loadCredentials]);

  const handleAddPasskey = async () => {
    setError('');
    setSuccess('');
    setRegistering(true);

    try {
      if (!window.PublicKeyCredential) {
        setError(t('error_not_supported'));
        setRegistering(false);
        return;
      }

      // Step 1: Begin registration
      const { session_id, options } = await beginRegister();

      // Step 2: Convert options for browser API
      const publicKeyOptions = options.publicKey;
      const credentialCreationOptions: CredentialCreationOptions = {
        publicKey: {
          rp: publicKeyOptions.rp,
          user: {
            id: base64URLToBuffer(publicKeyOptions.user.id),
            name: publicKeyOptions.user.name,
            displayName: publicKeyOptions.user.displayName,
          },
          challenge: base64URLToBuffer(publicKeyOptions.challenge),
          pubKeyCredParams: publicKeyOptions.pubKeyCredParams.map((p) => ({
            type: p.type as PublicKeyCredentialType,
            alg: p.alg,
          })),
          timeout: publicKeyOptions.timeout,
          excludeCredentials: (publicKeyOptions.excludeCredentials || []).map(
            (c) => ({
              type: c.type as PublicKeyCredentialType,
              id: base64URLToBuffer(c.id),
              transports: (c.transports || []) as AuthenticatorTransport[],
            }),
          ),
          authenticatorSelection: publicKeyOptions.authenticatorSelection
            ? {
                authenticatorAttachment:
                  publicKeyOptions.authenticatorSelection
                    .authenticatorAttachment as AuthenticatorAttachment,
                residentKey: publicKeyOptions.authenticatorSelection
                  .residentKey as ResidentKeyRequirement,
                requireResidentKey:
                  publicKeyOptions.authenticatorSelection.requireResidentKey,
                userVerification: publicKeyOptions.authenticatorSelection
                  .userVerification as UserVerificationRequirement,
              }
            : undefined,
          attestation:
            (publicKeyOptions.attestation as AttestationConveyancePreference) ||
            'none',
        },
      };

      // Step 3: Call WebAuthn API
      const credential = await navigator.credentials.create(
        credentialCreationOptions,
      );
      if (!credential) {
        setError(t('login_cancelled'));
        setRegistering(false);
        return;
      }

      // Step 4: Send attestation to server
      const name = newName.trim() || 'My Passkey';
      await finishRegister(session_id, name, credential);

      setSuccess(t('register_success'));
      setNewName('');
      setShowNameInput(false);
      await loadCredentials();
    } catch (err) {
      const message =
        err instanceof Error ? err.message : t('error_generic');
      if (
        message.includes('NotAllowedError') ||
        message.includes('AbortError')
      ) {
        setError(t('login_cancelled'));
      } else {
        setError(t('register_error').replace('${ERROR}', message));
      }
    } finally {
      setRegistering(false);
    }
  };

  const handleDelete = async () => {
    if (!deleteTarget) return;
    setError('');
    setSuccess('');

    try {
      await deleteCredential(deleteTarget.id);
      setSuccess(t('delete_success'));
      setDeleteTarget(null);
      await loadCredentials();
    } catch (err) {
      const message =
        err instanceof Error ? err.message : t('error_generic');
      setError(t('delete_error').replace('${ERROR}', message));
      setDeleteTarget(null);
    }
  };

  const handleTestPasskey = async () => {
    setError('');
    setSuccess('');
    setVerifiedCredId(null);
    if (verifiedTimerRef.current) {
      clearTimeout(verifiedTimerRef.current);
    }
    setTesting(true);

    try {
      if (!window.PublicKeyCredential) {
        setError(t('error_not_supported'));
        setTesting(false);
        return;
      }

      const { session_id, options } = await beginLogin();

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

      const credential = await navigator.credentials.get(
        credentialRequestOptions,
      );
      if (!credential) {
        setError(t('login_cancelled'));
        setTesting(false);
        return;
      }

      await finishLogin(session_id, credential);

      const usedCredId = (credential as PublicKeyCredential).id;
      setVerifiedCredId(usedCredId);
      setSuccess(t('test_success'));
      await loadCredentials();

      verifiedTimerRef.current = setTimeout(() => {
        setVerifiedCredId(null);
      }, 5000);
    } catch (err) {
      const message =
        err instanceof Error ? err.message : t('error_generic');
      if (
        message.includes('NotAllowedError') ||
        message.includes('AbortError')
      ) {
        setError(t('login_cancelled'));
      } else {
        setError(t('test_error').replace('${ERROR}', message));
      }
    } finally {
      setTesting(false);
    }
  };

  const formatDate = (dateStr: string): string => {
    if (!dateStr) return t('never_used');
    try {
      return new Date(dateStr).toLocaleDateString(undefined, {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
      });
    } catch {
      return dateStr;
    }
  };

  if (loading) {
    return (
      <div className="text-center py-4">
        <Spinner />
        <p className="mt-2 text-secondary">{t('loading')}</p>
      </div>
    );
  }

  return (
    <div>
      <h3 className="mb-3">{t('manage_title')}</h3>
      <p className="text-secondary">{t('manage_description')}</p>

      {error && (
        <Alert variant="danger" onClose={() => setError('')} dismissible>
          {error}
        </Alert>
      )}
      {success && (
        <Alert variant="success" onClose={() => setSuccess('')} dismissible>
          {success}
        </Alert>
      )}

      {credentials.length === 0 ? (
        <Alert variant="info">{t('no_passkeys')}</Alert>
      ) : (
        <ListGroup className="mb-3">
          {credentials.map((cred) => (
            <ListGroup.Item
              key={cred.id}
              variant={verifiedCredId === cred.id ? 'success' : undefined}
              className="d-flex justify-content-between align-items-start"
            >
              <div>
                <strong>{cred.name}</strong>
                <br />
                <small className="text-secondary">
                  {t('created')}: {formatDate(cred.created_at)}
                </small>
                <br />
                <small className="text-secondary">
                  {t('last_used')}:{' '}
                  {cred.last_used_at
                    ? formatDate(cred.last_used_at)
                    : t('never_used')}
                </small>
              </div>
              <Button
                variant="outline-danger"
                size="sm"
                onClick={() => setDeleteTarget(cred)}
              >
                {t('delete')}
              </Button>
            </ListGroup.Item>
          ))}
        </ListGroup>
      )}

      {showNameInput ? (
        <div className="mb-3">
          <Form.Group className="mb-2">
            <Form.Label>{t('passkey_name_label')}</Form.Label>
            <Form.Control
              type="text"
              placeholder={t('passkey_name_placeholder')}
              value={newName}
              onChange={(e) => setNewName(e.target.value)}
              disabled={registering}
            />
          </Form.Group>
          <div className="d-flex gap-2">
            <Button
              variant="primary"
              onClick={handleAddPasskey}
              disabled={registering}
            >
              {registering ? (
                <>
                  <Spinner size="sm" className="me-2" />
                  {t('loading')}
                </>
              ) : (
                t('save')
              )}
            </Button>
            <Button
              variant="outline-secondary"
              onClick={() => {
                setShowNameInput(false);
                setNewName('');
              }}
              disabled={registering}
            >
              {t('cancel')}
            </Button>
          </div>
        </div>
      ) : (
        <div className="d-flex gap-2">
          <Button
            variant="outline-primary"
            onClick={() => setShowNameInput(true)}
          >
            {t('add_passkey')}
          </Button>
          {credentials.length > 0 && (
            <Button
              variant="outline-secondary"
              onClick={handleTestPasskey}
              disabled={testing}
            >
              {testing ? (
                <>
                  <Spinner size="sm" className="me-2" />
                  {t('loading')}
                </>
              ) : (
                t('test_passkey')
              )}
            </Button>
          )}
        </div>
      )}

      {/* Delete confirmation modal */}
      <Modal show={!!deleteTarget} onHide={() => setDeleteTarget(null)}>
        <Modal.Header closeButton>
          <Modal.Title>{t('delete')}</Modal.Title>
        </Modal.Header>
        <Modal.Body>
          {t('delete_confirm')}
          {deleteTarget && (
            <p className="mt-2">
              <strong>{deleteTarget.name}</strong>
            </p>
          )}
        </Modal.Body>
        <Modal.Footer>
          <Button variant="secondary" onClick={() => setDeleteTarget(null)}>
            {t('cancel')}
          </Button>
          <Button variant="danger" onClick={handleDelete}>
            {t('delete')}
          </Button>
        </Modal.Footer>
      </Modal>
    </div>
  );
}

export default PasskeyManage;
