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

package passkey

import (
	"context"
	"time"

	"github.com/apache/answer-plugins/connector-passkey/internal/rp"
	"github.com/apache/answer-plugins/connector-passkey/internal/service"
	"github.com/apache/answer-plugins/connector-passkey/internal/store"
	"github.com/apache/answer/plugin"
	"github.com/segmentfault/pacman/log"
)

// ceremonyKeyInitTimeout bounds the eager ceremony key creation at start-up.
const ceremonyKeyInitTimeout = 10 * time.Second

// SetOperator implements plugin.KVStorage. The KV cache is disabled: every
// read must see the database (single-use challenges and tokens, shared
// ceremony key across instances).
//
// The ceremony key is created here, at start-up, so that the first
// unauthenticated login/begin does not have to write it. If that fails (for
// example the database is not reachable yet) the key is still created lazily
// on first use.
func (c *Connector) SetOperator(operator *plugin.KVOperator) {
	operator.Option(plugin.WithCacheTTL(-1))
	st := store.NewKV(operator)
	ctx, cancel := context.WithTimeout(context.Background(), ceremonyKeyInitTimeout)
	defer cancel()
	if _, err := st.CeremonyKey(ctx); err != nil {
		log.Warnf("passkey: create ceremony key at start-up: %v (retried on first use)", err)
	}
	c.svc.Store(service.New(service.Config{
		Store:        st,
		RelyingParty: c.relyingParty,
		ReceiverURL:  receiverURL,
		CeremonyTTL:  rp.CeremonyTimeout,
	}))
}
