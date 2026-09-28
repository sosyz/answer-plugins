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
	"reflect"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/segmentfault/pacman/log"
)

// coreUserKey is the core ctxUUIDKey (answer internal/base/middleware).
const coreUserKey = "ctxUuidKey"

// shapeWarning makes the unexpected-shape warning of loginUserID appear once
// per process. It is a pointer so that tests can reset it.
var shapeWarning = &sync.Once{}

// loginUserID returns the Answer user ID of the request, or "" when the
// request is not authenticated.
//
// The core auth middleware (answer internal/base/middleware/auth.go) stores
// the logged-in user under the gin key ctxUUIDKey = "ctxUuidKey" as a
// *entity.UserCacheInfo. Plugins cannot import internal packages, so the
// UserID string field is read by reflection. Upstream proposal: expose a
// public plugin.GetLoginUserID(ctx) helper and drop this reflection.
//
// It is only called from routes mounted behind the core auth middleware, so
// a missing key or a value of another shape means the core changed: every
// request is then treated as unauthenticated, and an error is logged once so
// that the breakage is visible.
func loginUserID(ctx *gin.Context) string {
	val, ok := ctx.Get(coreUserKey)
	if !ok {
		warnUnexpectedShape(nil)
		return ""
	}
	if val == nil {
		return ""
	}
	v := reflect.ValueOf(val)
	for v.Kind() == reflect.Pointer || v.Kind() == reflect.Interface {
		if v.IsNil() {
			return ""
		}
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		warnUnexpectedShape(val)
		return ""
	}
	f := v.FieldByName("UserID")
	if !f.IsValid() || f.Kind() != reflect.String {
		warnUnexpectedShape(val)
		return ""
	}
	return f.String()
}

func warnUnexpectedShape(val any) {
	shapeWarning.Do(func() {
		log.Errorf("passkey: cannot read the core login user from gin key %q (got %T, want a struct with a string UserID field); "+
			"passkey management treats every request as signed out until the plugin is updated for this Answer version",
			coreUserKey, val)
	})
}
