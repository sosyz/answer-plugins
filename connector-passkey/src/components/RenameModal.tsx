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

import { FormEvent, useEffect, useState } from 'react';
import { Button, Form, Modal, Spinner } from 'react-bootstrap';

import StatusAlert, { Status } from './StatusAlert';
import { MAX_NAME_LENGTH, normalizeName } from '../names';
import type { CredentialView } from '../types';
import { useT } from '../useT';
import { webauthnErrorKey } from '../webauthn';

const TITLE_ID = 'passkey-rename-title';

interface Props {
  /** The passkey being renamed; the modal is hidden when null. */
  credential: CredentialView | null;
  onCancel: () => void;
  onSubmit: (credential: CredentialView, name: string) => Promise<void>;
}

function RenameModal({ credential, onCancel, onSubmit }: Props) {
  const { t } = useT();
  const [name, setName] = useState('');
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState<Status | null>(null);

  useEffect(() => {
    setName(credential?.name ?? '');
    setBusy(false);
    setStatus(null);
  }, [credential]);

  const label = normalizeName(name);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (!credential || busy) {
      return;
    }
    if (!label) {
      setStatus({ variant: 'danger', key: 'error.invalid_name' });
      return;
    }
    setBusy(true);
    setStatus(null);
    try {
      await onSubmit(credential, label);
    } catch (err) {
      setBusy(false);
      setStatus({
        variant: 'danger',
        key: webauthnErrorKey(err) ?? 'error.unknown',
      });
    }
  };

  return (
    <Modal
      show={credential !== null}
      onHide={busy ? undefined : onCancel}
      aria-labelledby={TITLE_ID}
    >
      <Form onSubmit={handleSubmit} noValidate>
        <Modal.Header closeButton={!busy}>
          <Modal.Title as="h5" id={TITLE_ID}>
            {t('manage.rename_title')}
          </Modal.Title>
        </Modal.Header>
        <Modal.Body>
          <StatusAlert status={status} />
          <Form.Group controlId="passkey-rename-name">
            <Form.Label>{t('manage.name_label')}</Form.Label>
            <Form.Control
              type="text"
              value={name}
              maxLength={MAX_NAME_LENGTH}
              required
              autoFocus
              disabled={busy}
              placeholder={t('manage.name_placeholder')}
              onChange={(e) => setName(e.target.value)}
            />
          </Form.Group>
        </Modal.Body>
        <Modal.Footer>
          <Button variant="link" disabled={busy} onClick={onCancel}>
            {t('manage.cancel')}
          </Button>
          <Button
            type="submit"
            variant="primary"
            disabled={busy || name.trim() === ''}
          >
            {busy && <Spinner size="sm" className="me-2" aria-hidden="true" />}
            {t('manage.save')}
          </Button>
        </Modal.Footer>
      </Form>
    </Modal>
  );
}

export default RenameModal;
