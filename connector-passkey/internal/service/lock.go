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

package service

import (
	"hash/maphash"
	"sync"
)

// lockStripes is the fixed number of mutexes in a stripedMutex.
const lockStripes = 64

// stripedMutex serializes work on the same key within this process using a
// fixed set of mutexes, so memory stays bounded whatever the number of keys.
// Different keys may share a stripe; that only costs some waiting.
//
// The service uses four separate sets, acquired in this order only:
// challenge, then user handle, then credential. Tokens are never combined
// with another lock.
// Using one set for keys that are held together could self-deadlock when
// both keys fall on the same stripe.
type stripedMutex struct {
	seed    maphash.Seed
	stripes [lockStripes]sync.Mutex
}

func newStripedMutex() *stripedMutex {
	return &stripedMutex{seed: maphash.MakeSeed()}
}

// lock locks the stripe of key and returns its unlock function.
func (m *stripedMutex) lock(key string) (unlock func()) {
	mu := &m.stripes[maphash.String(m.seed, key)%lockStripes]
	mu.Lock()
	return mu.Unlock
}
