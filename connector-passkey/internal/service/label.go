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
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"
)

var errLabel = errors.New("passkey: invalid label")

// isBidiControl reports the bidirectional embedding, override and isolate
// controls (U+202A..U+202E, U+2066..U+2069), which can make a label read
// differently from what it is. Other format characters such as the zero
// width joiner used in emoji are kept.
func isBidiControl(r rune) bool {
	return (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069)
}

// sanitizeLabel trims s, drops control characters, bidirectional controls
// and invalid UTF-8, and rejects labels longer than maxLabelRunes or, when
// required, empty ones.
func sanitizeLabel(s string, required bool) (string, error) {
	s = strings.ToValidUTF8(s, "")
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || isBidiControl(r) {
			return -1
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if utf8.RuneCountInString(s) > maxLabelRunes || (required && s == "") {
		return "", errLabel
	}
	return s, nil
}
