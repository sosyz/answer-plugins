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

import { useEffect, useRef } from 'react';
import { Alert } from 'react-bootstrap';

import { useT } from '../useT';

export interface Status {
  variant: 'success' | 'danger' | 'warning' | 'info';
  /** i18n key relative to the plugin frontend prefix. */
  key: string;
}

interface Props {
  status: Status | null;
  onClose?: () => void;
}

/**
 * Announces success and error messages in a polite live region and moves
 * focus to the message so keyboard and screen reader users notice it.
 */
function StatusAlert({ status, onClose }: Props) {
  const { t } = useT();
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (status) {
      ref.current?.focus();
    }
  }, [status]);

  return (
    <div aria-live="polite" aria-atomic="true">
      {status && (
        <Alert
          ref={ref}
          tabIndex={-1}
          variant={status.variant}
          dismissible={Boolean(onClose)}
          onClose={onClose}
        >
          {t(status.key)}
        </Alert>
      )}
    </div>
  );
}

export default StatusAlert;
