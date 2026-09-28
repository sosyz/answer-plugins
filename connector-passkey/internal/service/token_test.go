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
	"context"
	"errors"
	"testing"

	"github.com/apache/answer-plugins/connector-passkey/internal/store/storetest"
)

func TestReceiverURL(t *testing.T) {
	for _, base := range []string{testReceiver, "/answer/api/v1/connector/redirect/passkey"} {
		svc := New(Config{Store: storetest.NewMemory(), ReceiverURL: func() string { return base }})
		if got, want := svc.receiverURL("t/1", "a b&c"), base+"?state=a+b%26c&token=t%2F1"; got != want {
			t.Errorf("receiverURL(%q) = %q, want %q", base, got, want)
		}
	}
}

func TestMintToken(t *testing.T) {
	raw, hash, err := mintToken()
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != 43 || len(hash) != 43 || hash != hashToken(raw) || raw == hash {
		t.Fatalf("raw %q hash %q", raw, hash)
	}
	raw2, _, _ := mintToken()
	if raw2 == raw {
		t.Fatal("tokens repeat")
	}
}

func TestRedeemLoginTokenRejects(t *testing.T) {
	svc := New(Config{Store: storetest.NewMemory()})
	ctx := context.Background()
	for _, tc := range [][2]string{{"", "s"}, {"t", ""}, {"unknown", "s"}} {
		if _, err := svc.RedeemLoginToken(ctx, tc[0], tc[1]); !errors.Is(err, ErrTokenInvalid) {
			t.Errorf("RedeemLoginToken(%q, %q) = %v", tc[0], tc[1], err)
		}
	}
}
