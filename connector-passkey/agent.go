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
	"errors"

	"github.com/apache/answer/plugin"
	"github.com/gin-gonic/gin"
)

var (
	errPluginDisabled = errors.New("passkey plugin is disabled")
	errNotReady       = errors.New("passkey storage is not initialized")
	errUnauthorized   = errors.New("login required")
)

// RegisterUnAuthRouter mounts the sign-in ceremony on /answer/api/v1/passkey.
func (c *Connector) RegisterUnAuthRouter(r *gin.RouterGroup) {
	c.routesMounted.Store(true)
	g := r.Group("/passkey", c.guard())
	g.POST("/login/begin", c.loginBegin)
	g.POST("/login/finish", c.loginFinish)
}

// RegisterAuthUserRouter mounts the logged-in user endpoints (behind the core
// MustAuthAndAccountAvailable middleware).
func (c *Connector) RegisterAuthUserRouter(r *gin.RouterGroup) {
	c.routesMounted.Store(true)
	g := r.Group("/passkey", c.guard())
	g.POST("/register/begin", c.registerBegin)
	g.POST("/register/finish", c.registerFinish)
	g.POST("/bind/begin", c.bindBegin)
	g.POST("/bind/finish", c.bindFinish)
	g.GET("/credentials", c.listCredentials)
	g.PATCH("/credentials/:id", c.renameCredential)
	g.DELETE("/credentials/:id", c.deleteCredential)
}

// RegisterAuthAdminRouter registers no route; like the other Register*
// methods it marks the start of the admin phase for ConfigReceiver.
func (c *Connector) RegisterAuthAdminRouter(_ *gin.RouterGroup) {
	c.routesMounted.Store(true)
}

// guard hides the routes while the plugin is disabled (the core mounts agent
// routes once at start-up, whatever the plugin status) and rejects calls
// until the KV storage has been attached.
func (c *Connector) guard() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		if !plugin.StatusManager.IsEnabled(slugName) {
			fail(ctx, errPluginDisabled)
			return
		}
		if c.svc.Load() == nil {
			fail(ctx, errNotReady)
			return
		}
		ctx.Next()
	}
}
