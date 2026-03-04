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
	"encoding/base64"
	"testing"
)

func TestEncodeBase64URL(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected string
	}{
		{
			name:     "empty",
			input:    []byte{},
			expected: "",
		},
		{
			name:     "single byte",
			input:    []byte{0xFF},
			expected: "_w",
		},
		{
			name:     "multiple bytes",
			input:    []byte{0x01, 0x02, 0x03},
			expected: "AQID",
		},
		{
			name:     "no padding needed",
			input:    []byte{0x01, 0x02, 0x03, 0x04},
			expected: "AQIDBA",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := base64.RawURLEncoding.EncodeToString(tt.input)
			if result != tt.expected {
				t.Errorf("encodeBase64URL() = %v, want %v", result, tt.expected)
			}

			// Verify round-trip
			decoded, err := base64.RawURLEncoding.DecodeString(result)
			if err != nil {
				t.Errorf("failed to decode: %v", err)
			}
			if string(decoded) != string(tt.input) {
				t.Errorf("round-trip failed: got %v, want %v", decoded, tt.input)
			}
		})
	}
}

func TestSessionDataExpiration(t *testing.T) {
	// Test that sessionTTL and tokenTTL are reasonable
	if sessionTTL.Minutes() < 1 {
		t.Error("sessionTTL should be at least 1 minute for WebAuthn ceremonies")
	}
	if sessionTTL.Minutes() > 10 {
		t.Error("sessionTTL should be less than 10 minutes for security")
	}

	if tokenTTL.Minutes() < 1 {
		t.Error("tokenTTL should be at least 1 minute")
	}
	if tokenTTL.Minutes() > 5 {
		t.Error("tokenTTL should be less than 5 minutes for security")
	}
}
