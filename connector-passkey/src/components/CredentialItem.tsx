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

import { Badge, Button, ListGroup } from 'react-bootstrap';

import type { CredentialView } from '../types';
import { formatDate, useT } from '../useT';

interface Props {
  credential: CredentialView;
  disabled: boolean;
  onRename: (credential: CredentialView) => void;
  onDelete: (credential: CredentialView) => void;
}

function CredentialItem({ credential, disabled, onRename, onDelete }: Props) {
  const { t, i18n } = useT();
  const name = credential.name || t('manage.default_name');
  const lang = i18n.language || 'en-US';

  return (
    <ListGroup.Item className="d-flex align-items-start justify-content-between gap-2">
      <div className="text-break">
        <div className="fw-semibold">
          {name}
          {credential.backup_state && (
            <Badge bg="secondary" className="ms-2 align-middle">
              {t('manage.synced')}
            </Badge>
          )}
        </div>
        <div className="small text-secondary">
          {t('manage.created', {
            date: formatDate(credential.created_at, lang),
          })}
        </div>
        <div className="small text-secondary">
          {credential.last_used_at
            ? t('manage.last_used', {
                date: formatDate(credential.last_used_at, lang),
              })
            : t('manage.never_used')}
        </div>
      </div>
      <div className="d-flex flex-shrink-0 gap-1">
        <Button
          size="sm"
          variant="outline-secondary"
          disabled={disabled}
          aria-label={t('manage.rename_named', { name })}
          onClick={() => onRename(credential)}
        >
          {t('manage.rename')}
        </Button>
        <Button
          size="sm"
          variant="outline-danger"
          disabled={disabled}
          aria-label={t('manage.delete_named', { name })}
          onClick={() => onDelete(credential)}
        >
          {t('manage.delete')}
        </Button>
      </div>
    </ListGroup.Item>
  );
}

export default CredentialItem;
