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
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/segmentfault/pacman/log"
)

type fakeUserCacheInfo struct {
	UserID string
	Other  int
}

func TestLoginUserID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, tc := range []struct {
		name string
		val  any
		set  bool
		want string
	}{
		{name: "pointer to struct", val: &fakeUserCacheInfo{UserID: "42"}, set: true, want: "42"},
		{name: "struct value", val: fakeUserCacheInfo{UserID: "7"}, set: true, want: "7"},
		{name: "missing key"},
		{name: "nil value", val: nil, set: true},
		{name: "nil pointer", val: (*fakeUserCacheInfo)(nil), set: true},
		{name: "non-struct", val: "42", set: true},
		{name: "struct without UserID", val: &struct{ ID string }{ID: "1"}, set: true},
		{name: "non-string UserID", val: &struct{ UserID int }{UserID: 1}, set: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := &gin.Context{}
			if tc.set {
				ctx.Set("ctxUuidKey", tc.val)
			}
			if got := loginUserID(ctx); got != tc.want {
				t.Fatalf("loginUserID = %q, want %q", got, tc.want)
			}
		})
	}
}

// captureLogger records Error and Warn messages.
type captureLogger struct {
	log.Logger
	mu   sync.Mutex
	msgs []string
}

func (l *captureLogger) Errorf(format string, v ...any) { l.add(format, v...) }
func (l *captureLogger) Warnf(format string, v ...any)  { l.add(format, v...) }

func (l *captureLogger) add(format string, v ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.msgs = append(l.msgs, fmt.Sprintf(format, v...))
}

// TestLoginUserIDUnexpectedShapeLogsOnce checks that a core change of the
// login user value (a missing key or another shape) is reported, once per
// process, while a nil value is not.
func TestLoginUserIDUnexpectedShapeLogsOnce(t *testing.T) {
	gin.SetMode(gin.TestMode)
	prev := log.GetLogger()
	logger := &captureLogger{Logger: prev}
	log.SetLogger(logger)
	shapeWarning = &sync.Once{}
	t.Cleanup(func() {
		log.SetLogger(prev)
		shapeWarning = &sync.Once{}
	})

	get := func(val any, set bool) string {
		ctx := &gin.Context{}
		if set {
			ctx.Set("ctxUuidKey", val)
		}
		return loginUserID(ctx)
	}
	get(nil, true)
	get((*fakeUserCacheInfo)(nil), true)
	get(&fakeUserCacheInfo{UserID: "1"}, true)
	if len(logger.msgs) != 0 {
		t.Fatalf("expected shapes logged %q", logger.msgs)
	}

	// The routes are behind the core auth middleware, so a missing key means
	// the core renamed it.
	get(nil, false)
	get(nil, false)
	if len(logger.msgs) != 1 || !strings.Contains(logger.msgs[0], "ctxUuidKey") {
		t.Fatalf("missing key logged %q, want one message", logger.msgs)
	}
	logger.msgs = nil
	shapeWarning = &sync.Once{}

	type renamed struct{ UID string }
	for range 3 {
		if got := get(&renamed{UID: "42"}, true); got != "" {
			t.Fatalf("loginUserID = %q for an unexpected shape", got)
		}
		if got := get(map[string]string{"UserID": "42"}, true); got != "" {
			t.Fatalf("loginUserID = %q for a map", got)
		}
	}
	if len(logger.msgs) != 1 || !strings.Contains(logger.msgs[0], "ctxUuidKey") || !strings.Contains(logger.msgs[0], "renamed") {
		t.Fatalf("logged %q, want one message naming the key and type", logger.msgs)
	}
}
