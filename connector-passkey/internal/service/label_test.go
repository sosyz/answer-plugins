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
	"strings"
	"testing"
)

func TestSanitizeLabel(t *testing.T) {
	for _, tc := range []struct {
		in       string
		required bool
		want     string
		wantErr  bool
	}{
		{in: "  MacBook Touch ID  ", want: "MacBook Touch ID"},
		{in: "a\x00b\x1fc\x7fd\u0085e", want: "abcde"},
		{in: "line\nbreak\ttab", want: "linebreaktab"},
		{in: "bad\xffutf8", want: "badutf8"},
		{in: "", want: ""},
		{in: "", required: true, wantErr: true},
		{in: " \n\t", required: true, wantErr: true},
		{in: strings.Repeat("密", 64), want: strings.Repeat("密", 64)},
		{in: strings.Repeat("密", 65), wantErr: true},
		{in: strings.Repeat("x", 64) + "\x00\x00", want: strings.Repeat("x", 64)},
		{in: "Work\u202Ekey", want: "Workkey"},
		{in: "\u2066a\u2067b\u2068c\u2069\u202Ad\u202B\u202C\u202D", want: "abcd"},
		{in: "👩\u200D💻 laptop", want: "👩\u200D💻 laptop"},
	} {
		got, err := sanitizeLabel(tc.in, tc.required)
		if (err != nil) != tc.wantErr || got != tc.want {
			t.Errorf("sanitizeLabel(%q, %v) = %q, %v", tc.in, tc.required, got, err)
		}
	}
}
