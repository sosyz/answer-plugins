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
	"testing"
)

func TestValidateRPID(t *testing.T) {
	tests := []struct {
		name    string
		rpid    string
		wantErr bool
	}{
		{"valid domain", "example.com", false},
		{"valid subdomain", "answer.example.com", false},
		{"valid with numbers", "api123.example.com", false},
		{"empty string", "", true},
		{"too long", string(make([]byte, 300)), true},
		{"invalid characters", "example$.com", true},
		{"starts with hyphen", "-example.com", true},
		{"ends with hyphen", "example-.com", true},
		{"localhost", "localhost", false},
		{"IP address (invalid for RPID)", "192.168.1.1", false}, // technically valid format
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRPID(tt.rpid)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateRPID() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateOrigin(t *testing.T) {
	tests := []struct {
		name    string
		origin  string
		wantErr bool
	}{
		{"valid HTTPS", "https://example.com", false},
		{"valid HTTP", "http://localhost:3000", false},
		{"valid with port", "https://example.com:8443", false},
		{"valid with path", "https://example.com/path", false},
		{"empty string", "", true},
		{"too long", "https://" + string(make([]byte, 2100)), true},
		{"invalid scheme", "ftp://example.com", true},
		{"no scheme", "example.com", true},
		{"no hostname", "https://", true},
		{"invalid URL", "not-a-url", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateOrigin(tt.origin)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateOrigin() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestParseOrigins(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{"single origin", "https://example.com", []string{"https://example.com"}},
		{"multiple origins", "https://a.com,https://b.com", []string{"https://a.com", "https://b.com"}},
		{"with spaces", "https://a.com, https://b.com", []string{"https://a.com", "https://b.com"}},
		{"empty parts", "https://a.com,,https://b.com", []string{"https://a.com", "https://b.com"}},
		{"empty string", "", []string{}},
		{"only spaces", "   ", []string{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseOrigins(tt.input)
			if len(result) != len(tt.expected) {
				t.Errorf("parseOrigins() got %d items, want %d", len(result), len(tt.expected))
				return
			}
			for i := range result {
				if result[i] != tt.expected[i] {
					t.Errorf("parseOrigins()[%d] = %v, want %v", i, result[i], tt.expected[i])
				}
			}
		})
	}
}

func TestConfigReceiver(t *testing.T) {
	tests := []struct {
		name    string
		config  string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid config",
			config:  `{"rp_name":"Test","rp_id":"example.com","rp_origins":"https://example.com","attestation_type":"none"}`,
			wantErr: false,
		},
		{
			name:    "missing rp_name",
			config:  `{"rp_id":"example.com","rp_origins":"https://example.com"}`,
			wantErr: true,
			errMsg:  "RP Name is required",
		},
		{
			name:    "missing rp_id",
			config:  `{"rp_name":"Test","rp_origins":"https://example.com"}`,
			wantErr: true,
			errMsg:  "RP ID is required",
		},
		{
			name:    "missing rp_origins",
			config:  `{"rp_name":"Test","rp_id":"example.com"}`,
			wantErr: true,
			errMsg:  "at least one origin is required",
		},
		{
			name:    "invalid RPID",
			config:  `{"rp_name":"Test","rp_id":"invalid$domain","rp_origins":"https://example.com"}`,
			wantErr: true,
			errMsg:  "invalid RP ID",
		},
		{
			name:    "invalid origin",
			config:  `{"rp_name":"Test","rp_id":"example.com","rp_origins":"not-a-url"}`,
			wantErr: true,
			errMsg:  "invalid origin",
		},
		{
			name:    "invalid attestation type",
			config:  `{"rp_name":"Test","rp_id":"example.com","rp_origins":"https://example.com","attestation_type":"invalid"}`,
			wantErr: true,
			errMsg:  "invalid attestation type",
		},
		{
			name:    "rp_name too long",
			config:  `{"rp_name":"` + generateLongString(300) + `","rp_id":"example.com","rp_origins":"https://example.com"}`,
			wantErr: true,
			errMsg:  "RP Name must be 255 characters or less",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Connector{}
			err := c.ConfigReceiver([]byte(tt.config))
			if (err != nil) != tt.wantErr {
				t.Errorf("ConfigReceiver() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil && tt.errMsg != "" {
				if !contains(err.Error(), tt.errMsg) {
					t.Errorf("ConfigReceiver() error = %v, want error containing %v", err, tt.errMsg)
				}
			}
		})
	}
}

func generateLongString(length int) string {
	result := make([]byte, length)
	for i := range result {
		result[i] = 'a'
	}
	return string(result)
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr || containsSubstring(s, substr)))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
