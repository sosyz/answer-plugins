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

package rp

import (
	"errors"
	"reflect"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
)

func TestResolve(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		site    string
		want    Settings
		wantErr bool
	}{
		{
			name: "defaults from site URL",
			site: "https://example.com",
			want: Settings{Name: "example.com", ID: "example.com", Origins: []string{"https://example.com"}},
		},
		{
			name: "defaults from sub-path site URL",
			site: "https://Example.com/community/",
			want: Settings{Name: "example.com", ID: "example.com", Origins: []string{"https://example.com"}},
		},
		{
			name: "site URL port is kept in the origin",
			site: "https://example.com:8443/qa",
			want: Settings{Name: "example.com", ID: "example.com", Origins: []string{"https://example.com:8443"}},
		},
		{
			name: "localhost over http",
			site: "http://localhost:9080",
			want: Settings{Name: "localhost", ID: "localhost", Origins: []string{"http://localhost:9080"}},
		},
		{
			name:    "http on a public host is rejected",
			site:    "http://example.com",
			wantErr: true,
		},
		{
			name:    "IP site URL cannot be an RP ID",
			site:    "https://192.0.2.10",
			wantErr: true,
		},
		{
			name: "explicit values win",
			cfg:  Config{Name: "My Q&A", ID: "example.com", Origins: "https://qa.example.com"},
			site: "https://qa.example.com",
			want: Settings{Name: "My Q&A", ID: "example.com", Origins: []string{"https://qa.example.com"}},
		},
		{
			name: "comma and newline separators, trailing slash, duplicates",
			cfg:  Config{ID: "example.com", Origins: " https://example.com/,https://a.example.com\nhttps://example.com\r\nhttps://B.example.com:443 "},
			site: "https://example.com",
			want: Settings{Name: "example.com", ID: "example.com", Origins: []string{"https://example.com", "https://a.example.com", "https://b.example.com"}},
		},
		{
			name:    "origin on another domain",
			cfg:     Config{Origins: "https://evil.example.org"},
			site:    "https://example.com",
			wantErr: true,
		},
		{
			name:    "suffix without a dot is not a subdomain",
			cfg:     Config{Origins: "https://notexample.com"},
			site:    "https://example.com",
			wantErr: true,
		},
		{
			name: "explicit config without site URL",
			cfg:  Config{ID: "example.com", Origins: "https://example.com"},
			want: Settings{Name: "example.com", ID: "example.com", Origins: []string{"https://example.com"}},
		},
		{
			name:    "empty config and empty site URL",
			wantErr: true,
		},
		{
			name:    "ID without origins and without site URL",
			cfg:     Config{ID: "example.com"},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.cfg.Resolve(tt.site)
			if tt.wantErr {
				if !errors.Is(err, ErrNotConfigured) {
					t.Fatalf("Resolve() error = %v, want ErrNotConfigured", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Resolve() error = %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("Resolve() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		site    string
		wantErr bool
	}{
		{name: "all empty with site URL", site: "https://example.com"},
		{name: "all empty without site URL"},
		{name: "subdomain origin", cfg: Config{Origins: "https://qa.example.com"}, site: "https://example.com"},
		{name: "uppercase ID is normalized", cfg: Config{ID: " Example.COM "}, site: "https://example.com"},
		{name: "localhost ID", cfg: Config{ID: "localhost", Origins: "http://localhost:3000"}},
		{name: "ID with scheme", cfg: Config{ID: "https://example.com"}, wantErr: true},
		{name: "ID with port", cfg: Config{ID: "example.com:443"}, wantErr: true},
		{name: "ID with path", cfg: Config{ID: "example.com/qa"}, wantErr: true},
		{name: "IPv4 ID", cfg: Config{ID: "192.0.2.1"}, wantErr: true},
		{name: "IPv6 ID", cfg: Config{ID: "::1"}, wantErr: true},
		{name: "single label ID", cfg: Config{ID: "intranet"}, wantErr: true},
		{name: "http origin on public host", cfg: Config{Origins: "http://example.com"}, wantErr: true},
		{name: "origin with path", cfg: Config{Origins: "https://example.com/qa"}, wantErr: true},
		{name: "origin with query", cfg: Config{Origins: "https://example.com/?a=b"}, wantErr: true},
		{name: "origin with fragment", cfg: Config{Origins: "https://example.com#x"}, wantErr: true},
		{name: "origin with userinfo", cfg: Config{Origins: "https://u:p@example.com"}, wantErr: true},
		{name: "origin without scheme", cfg: Config{Origins: "example.com"}, wantErr: true},
		{name: "origin outside ID without site URL", cfg: Config{ID: "example.com", Origins: "https://example.org"}, wantErr: true},
		{name: "origin outside site-derived ID", cfg: Config{Origins: "https://example.org"}, site: "https://example.com", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate(tt.site)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSettingsWebAuthn(t *testing.T) {
	w, err := Settings{Name: "Example", ID: "example.com", Origins: []string{"https://example.com"}}.WebAuthn()
	if err != nil {
		t.Fatal(err)
	}
	c := w.Config
	if c.AttestationPreference != protocol.PreferNoAttestation {
		t.Errorf("attestation = %q", c.AttestationPreference)
	}
	sel := c.AuthenticatorSelection
	if sel.ResidentKey != protocol.ResidentKeyRequirementRequired || sel.RequireResidentKey == nil || !*sel.RequireResidentKey {
		t.Errorf("resident key selection = %+v", sel)
	}
	if sel.UserVerification != protocol.VerificationRequired {
		t.Errorf("user verification = %q", sel.UserVerification)
	}
	for _, tc := range []struct {
		name string
		got  bool
	}{
		{"login enforce", c.Timeouts.Login.Enforce},
		{"registration enforce", c.Timeouts.Registration.Enforce},
		{"login timeout", c.Timeouts.Login.Timeout == CeremonyTimeout && c.Timeouts.Login.TimeoutUVD == CeremonyTimeout},
		{"registration timeout", c.Timeouts.Registration.Timeout == CeremonyTimeout && c.Timeouts.Registration.TimeoutUVD == CeremonyTimeout},
	} {
		if !tc.got {
			t.Errorf("%s not set", tc.name)
		}
	}
}
