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

import { useEffect, useState } from 'react';
import { Alert, Button, Modal, Spinner } from 'react-bootstrap';

import StatusAlert, { Status } from './StatusAlert';
import { accountSettingsURL } from '../navigation';
import type { CredentialView, LinkState } from '../types';
import { useT } from '../useT';
import { webauthnErrorKey } from '../webauthn';

interface Props {
  /** The passkey being deleted; the modal is hidden when null. */
  credential: CredentialView | null;
  /** True when this is the user's only passkey. */
  isLast: boolean;
  /** Whether the account is linked to passkeys in the core. */
  link: LinkState;
  onRetryLink: () => void;
  onCancel: () => void;
  onConfirm: (credential: CredentialView) => Promise<void>;
}

const TITLE_ID = 'passkey-delete-title';

/**
 * Confirms deleting a passkey. The last passkey of a linked account cannot be
 * deleted here (see ManageView); neither can it while the link state is
 * unknown.
 */
function DeleteModal({
  credential,
  isLast,
  link,
  onRetryLink,
  onCancel,
  onConfirm,
}: Props) {
  const { t } = useT();
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState<Status | null>(null);

  useEffect(() => {
    setBusy(false);
    setStatus(null);
  }, [credential]);

  const blocked = isLast && link !== 'unlinked';

  const handleConfirm = async () => {
    if (!credential || busy || blocked) {
      return;
    }
    setBusy(true);
    setStatus(null);
    try {
      await onConfirm(credential);
    } catch (err) {
      setBusy(false);
      setStatus({
        variant: 'danger',
        key: webauthnErrorKey(err) ?? 'error.unknown',
      });
    }
  };

  const name = credential?.name || t('manage.default_name');

  let lastNotice = null;
  if (isLast) {
    switch (link) {
      case 'unlinked':
        lastNotice = (
          <Alert variant="warning">{t('manage.delete_last_warning')}</Alert>
        );
        break;
      case 'linked':
        lastNotice = (
          <Alert variant="warning">
            <p>{t('manage.delete_last_linked')}</p>
            <a href={accountSettingsURL()} className="alert-link">
              {t('manage.account_settings_link')}
            </a>
          </Alert>
        );
        break;
      case 'loading':
        lastNotice = (
          <div role="status" className="d-flex align-items-center gap-2 mb-3">
            <Spinner size="sm" aria-hidden="true" />
            <span>{t('manage.link_checking')}</span>
          </div>
        );
        break;
      case 'error':
        lastNotice = (
          <Alert variant="danger">
            <p>{t('manage.link_check_failed')}</p>
            <Button size="sm" variant="outline-danger" onClick={onRetryLink}>
              {t('manage.retry')}
            </Button>
          </Alert>
        );
        break;
    }
  }

  return (
    <Modal
      show={credential !== null}
      onHide={busy ? undefined : onCancel}
      aria-labelledby={TITLE_ID}
    >
      <Modal.Header closeButton={!busy}>
        <Modal.Title as="h5" id={TITLE_ID}>
          {t('manage.delete_title')}
        </Modal.Title>
      </Modal.Header>
      <Modal.Body>
        <StatusAlert status={status} />
        <p className="text-break">{t('manage.delete_confirm', { name })}</p>
        <div aria-live="polite">{lastNotice}</div>
        <p className="small text-secondary mb-0">
          {t('manage.delete_device_hint')}
        </p>
      </Modal.Body>
      <Modal.Footer>
        <Button variant="link" disabled={busy} onClick={onCancel}>
          {t('manage.cancel')}
        </Button>
        <Button
          variant="danger"
          disabled={busy || blocked}
          onClick={handleConfirm}
        >
          {busy && <Spinner size="sm" className="me-2" aria-hidden="true" />}
          {t('manage.delete')}
        </Button>
      </Modal.Footer>
    </Modal>
  );
}

export default DeleteModal;
