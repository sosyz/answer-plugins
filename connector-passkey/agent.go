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
	"github.com/gin-gonic/gin"
)

// RegisterUnAuthRouter registers unauthenticated routes (login ceremony).
func (c *Connector) RegisterUnAuthRouter(r *gin.RouterGroup) {
	r.POST("/passkey/begin-login", c.handleBeginLogin)
	r.POST("/passkey/finish-login", c.handleFinishLogin)
}

// RegisterAuthUserRouter registers authenticated user routes (registration + management).
func (c *Connector) RegisterAuthUserRouter(r *gin.RouterGroup) {
	r.POST("/passkey/begin-register", c.handleBeginRegister)
	r.POST("/passkey/finish-register", c.handleFinishRegister)
	r.GET("/passkey/credentials", c.handleListCredentials)
	r.DELETE("/passkey/credentials/:id", c.handleDeleteCredential)
}

// RegisterAuthAdminRouter registers admin-only routes (none needed for this plugin).
func (c *Connector) RegisterAuthAdminRouter(r *gin.RouterGroup) {
	// No admin-only routes needed
}
