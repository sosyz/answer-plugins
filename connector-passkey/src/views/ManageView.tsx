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

import { FormEvent, useCallback, useEffect, useRef, useState } from 'react';
import { Alert, Button, Form, ListGroup, Spinner } from 'react-bootstrap';

import { getPasskeyConnector } from '../api/core';
import {
  deleteCredential,
  listCredentials,
  registerBegin,
  registerFinish,
  renameCredential,
} from '../api/passkey';
import CredentialItem from '../components/CredentialItem';
import DeleteModal from '../components/DeleteModal';
import RenameModal from '../components/RenameModal';
import StatusAlert, { Status } from '../components/StatusAlert';
import { MAX_NAME_LENGTH, normalizeName } from '../names';
import { bindURL, safeRedirect } from '../navigation';
import type {
  CredentialView,
  CurrentUser,
  LinkState,
  PasskeyConnector,
} from '../types';
import { useT } from '../useT';
import { cancel, register, supported, webauthnErrorKey } from '../webauthn';

interface Props {
  user: CurrentUser;
}

const linkStateOf = (connector: PasskeyConnector | null): LinkState =>
  connector === null ? 'error' : connector.binding ? 'linked' : 'unlinked';

/** Lists, adds, renames and deletes the signed-in user's passkeys. */
function ManageView({ user }: Props) {
  const { t } = useT();
  const [credentials, setCredentials] = useState<CredentialView[] | null>(null);
  const [link, setLink] = useState<LinkState>('loading');
  const [name, setName] = useState('');
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState<Status | null>(null);
  const [renaming, setRenaming] = useState<CredentialView | null>(null);
  const [deleting, setDeleting] = useState<CredentialView | null>(null);
  const alive = useRef(true);
  // Only the newest connector lookup may set the link state.
  const linkLookup = useRef(0);

  const showError = (err: unknown) => {
    const key = webauthnErrorKey(err);
    if (key) {
      setStatus({ variant: 'danger', key });
    }
  };

  /**
   * Looks up whether the account is linked to passkeys in the core. A missing
   * passkey entry counts as a failed lookup.
   */
  const refreshLink = useCallback(async () => {
    const id = ++linkLookup.current;
    setLink('loading');
    let next: LinkState;
    try {
      next = linkStateOf(await getPasskeyConnector());
    } catch {
      next = 'error';
    }
    if (alive.current && linkLookup.current === id) {
      setLink(next);
    }
  }, []);

  useEffect(() => {
    alive.current = true;
    listCredentials()
      .then((list) => alive.current && setCredentials(list))
      .catch((err) => {
        if (alive.current) {
          setCredentials([]);
          showError(err);
        }
      });
    void refreshLink();
    return () => {
      alive.current = false;
      cancel();
    };
  }, [refreshLink]);

  /** The typed name, or null (with an error shown) when it is invalid. */
  const validName = (): string | null => {
    const label = normalizeName(name);
    if (label === null) {
      setStatus({ variant: 'danger', key: 'error.invalid_name' });
    }
    return label;
  };

  /**
   * Continues in the bind view of this page, which links the account through
   * the core bind flow and names a new passkey `label`.
   */
  const goToBind = (label: string) => {
    setBusy(true);
    window.location.assign(bindURL(label));
  };

  const handleLink = () => {
    const label = validName();
    if (label !== null) {
      setStatus(null);
      goToBind(label);
    }
  };

  const handleAdd = async (e: FormEvent) => {
    e.preventDefault();
    if (busy) {
      return;
    }
    const label = validName();
    if (label === null) {
      return;
    }
    setStatus(null);
    setBusy(true);
    try {
      // An unlinked account adds its passkey through the bind view. Checked
      // afresh: the account may have been linked or unlinked meanwhile.
      const id = ++linkLookup.current;
      const next = linkStateOf(await getPasskeyConnector());
      if (!alive.current) {
        return;
      }
      if (linkLookup.current === id) {
        setLink(next);
      }
      if (next === 'unlinked') {
        goToBind(label);
        return;
      }
      const { session, options } = await registerBegin({
        user_name: user.username,
        display_name: user.display_name,
      });
      const credential = await register(options);
      const result = await registerFinish({ session, name: label, credential });
      if (!alive.current) {
        return;
      }
      if (result.redirect_url) {
        safeRedirect(result.redirect_url);
        return;
      }
      setCredentials((list) => [...(list ?? []), result.credential]);
      setName('');
      setBusy(false);
      setStatus({ variant: 'success', key: 'manage.add_success' });
    } catch (err) {
      if (alive.current) {
        setBusy(false);
        showError(err);
      }
    }
  };

  const handleRename = async (target: CredentialView, newName: string) => {
    if (newName === target.name) {
      setRenaming(null);
      return;
    }
    const updated = await renameCredential(target.id, newName);
    if (!alive.current) {
      return;
    }
    setCredentials((list) =>
      (list ?? []).map((c) => (c.id === updated.id ? updated : c)),
    );
    setRenaming(null);
    setStatus({ variant: 'success', key: 'manage.rename_success' });
  };

  const isLast = credentials?.length === 1;

  // The plugin cannot see the core's login bindings, so it cannot enforce the
  // core rule that the last login method of an account stays. Deleting the
  // last passkey of a linked account would leave a binding nobody can sign in
  // with; the user has to unbind it under My logins first, where the core
  // applies that rule.
  const deleteBlocked = isLast && link !== 'unlinked';

  const openDelete = (target: CredentialView) => {
    setDeleting(target);
    if (isLast) {
      void refreshLink();
    }
  };

  const handleDelete = async (target: CredentialView) => {
    if (deleteBlocked) {
      return;
    }
    await deleteCredential(target.id);
    if (!alive.current) {
      return;
    }
    setCredentials((list) => (list ?? []).filter((c) => c.id !== target.id));
    setDeleting(null);
    setStatus({ variant: 'success', key: 'manage.delete_success' });
  };

  const hasCredentials = Boolean(credentials && credentials.length > 0);

  return (
    <>
      <h3 className="mb-3">{t('manage.title')}</h3>
      <p className="text-secondary">{t('manage.description')}</p>

      <StatusAlert status={status} onClose={() => setStatus(null)} />

      {link === 'unlinked' && hasCredentials && (
        <Alert variant="warning">
          <p>{t('manage.not_linked')}</p>
          <Button variant="warning" disabled={busy} onClick={handleLink}>
            {t('manage.link_button')}
          </Button>
        </Alert>
      )}

      {credentials === null ? (
        <div role="status" className="d-flex align-items-center gap-2 py-3">
          <Spinner size="sm" aria-hidden="true" />
          <span>{t('common.loading')}</span>
        </div>
      ) : credentials.length === 0 ? (
        <p className="text-secondary py-2">{t('manage.empty')}</p>
      ) : (
        <ListGroup className="mb-4">
          {credentials.map((c) => (
            <CredentialItem
              key={c.id}
              credential={c}
              disabled={busy}
              onRename={setRenaming}
              onDelete={openDelete}
            />
          ))}
        </ListGroup>
      )}

      {!supported ? (
        <Alert variant="warning">{t('webauthn.not_supported')}</Alert>
      ) : (
        <Form onSubmit={handleAdd} noValidate>
          <Form.Group className="mb-3" controlId="passkey-new-name">
            <Form.Label>{t('manage.name_label')}</Form.Label>
            <Form.Control
              type="text"
              value={name}
              maxLength={MAX_NAME_LENGTH}
              disabled={busy}
              placeholder={t('manage.name_placeholder')}
              onChange={(e) => setName(e.target.value)}
            />
          </Form.Group>
          <Button
            type="submit"
            variant="primary"
            disabled={busy || credentials === null}
          >
            {busy && <Spinner size="sm" className="me-2" aria-hidden="true" />}
            {t('manage.add_button')}
          </Button>
        </Form>
      )}

      <RenameModal
        credential={renaming}
        onCancel={() => setRenaming(null)}
        onSubmit={handleRename}
      />
      <DeleteModal
        credential={deleting}
        isLast={isLast}
        link={link}
        onRetryLink={() => void refreshLink()}
        onCancel={() => setDeleting(null)}
        onConfirm={handleDelete}
      />
    </>
  );
}

export default ManageView;
