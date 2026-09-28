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
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/apache/answer-plugins/connector-passkey/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/go-webauthn/webauthn/protocol"
)

const maxBodyBytes = 64 << 10

type loginBeginReq struct {
	State      string `json:"state"`
	StateProof string `json:"state_proof"`
}

type finishReq struct {
	Session    string          `json:"session"`
	Credential json.RawMessage `json:"credential"`
}

type registerBeginReq struct {
	UserName    string `json:"user_name"`
	DisplayName string `json:"display_name"`
	State       string `json:"state"`
}

type registerFinishReq struct {
	Session    string          `json:"session"`
	Name       string          `json:"name"`
	Credential json.RawMessage `json:"credential"`
}

type bindBeginReq struct {
	State string `json:"state"`
}

type renameReq struct {
	Name string `json:"name"`
}

type creationResp struct {
	Session string                                      `json:"session"`
	Options protocol.PublicKeyCredentialCreationOptions `json:"options"`
}

type assertionResp struct {
	Session string                                     `json:"session"`
	Options protocol.PublicKeyCredentialRequestOptions `json:"options"`
}

type redirectResp struct {
	RedirectURL string `json:"redirect_url"`
}

type registerFinishResp struct {
	Credential  credentialView `json:"credential"`
	RedirectURL string         `json:"redirect_url"`
}

type credentialResp struct {
	Credential credentialView `json:"credential"`
}

type credentialsResp struct {
	Credentials []credentialView `json:"credentials"`
}

// decode reads a JSON body of at most maxBodyBytes into dst.
func decode(ctx *gin.Context, dst any) error {
	body := http.MaxBytesReader(ctx.Writer, ctx.Request.Body, maxBodyBytes)
	if err := json.NewDecoder(body).Decode(dst); err != nil {
		return fmt.Errorf("%w: %v", service.ErrInvalidInput, err)
	}
	return nil
}

func decodeFinish(ctx *gin.Context, session *string, credential *json.RawMessage, dst any) error {
	if err := decode(ctx, dst); err != nil {
		return err
	}
	if *session == "" || len(*credential) == 0 || string(*credential) == "null" {
		return fmt.Errorf("%w: session and credential are required", service.ErrInvalidInput)
	}
	return nil
}

func encodeID(id []byte) string {
	return base64.RawURLEncoding.EncodeToString(id)
}

func pathID(ctx *gin.Context) ([]byte, error) {
	id, err := base64.RawURLEncoding.DecodeString(ctx.Param("id"))
	if err != nil || len(id) == 0 {
		return nil, fmt.Errorf("%w: credential id", service.ErrInvalidInput)
	}
	return id, nil
}

// authUser returns the caller's Answer user ID, writing a 401 when missing.
func authUser(ctx *gin.Context) (string, bool) {
	id := loginUserID(ctx)
	if id == "" {
		fail(ctx, errUnauthorized)
		return "", false
	}
	return id, true
}

func (c *Connector) loginBegin(ctx *gin.Context) {
	var req loginBeginReq
	if err := decode(ctx, &req); err != nil {
		fail(ctx, err)
		return
	}
	cer, err := c.svc.Load().BeginLogin(ctx.Request.Context(), req.State, req.StateProof)
	if err != nil {
		fail(ctx, err)
		return
	}
	ok(ctx, assertionResp{Session: cer.Session, Options: cer.Options})
}

func (c *Connector) loginFinish(ctx *gin.Context) {
	var req finishReq
	if err := decodeFinish(ctx, &req.Session, &req.Credential, &req); err != nil {
		fail(ctx, err)
		return
	}
	redirect, err := c.svc.Load().FinishLogin(ctx.Request.Context(), req.Session, req.Credential)
	if err != nil {
		fail(ctx, err)
		return
	}
	ok(ctx, redirectResp{RedirectURL: redirect})
}

func (c *Connector) registerBegin(ctx *gin.Context) {
	uid, authed := authUser(ctx)
	if !authed {
		return
	}
	var req registerBeginReq
	if err := decode(ctx, &req); err != nil {
		fail(ctx, err)
		return
	}
	label := service.UserLabel{Name: req.UserName, DisplayName: req.DisplayName}
	cer, err := c.svc.Load().BeginRegistration(ctx.Request.Context(), uid, label, req.State)
	if err != nil {
		fail(ctx, err)
		return
	}
	ok(ctx, creationResp{Session: cer.Session, Options: cer.Options})
}

func (c *Connector) registerFinish(ctx *gin.Context) {
	uid, authed := authUser(ctx)
	if !authed {
		return
	}
	var req registerFinishReq
	if err := decodeFinish(ctx, &req.Session, &req.Credential, &req); err != nil {
		fail(ctx, err)
		return
	}
	cred, redirect, err := c.svc.Load().FinishRegistration(ctx.Request.Context(), uid, req.Session, req.Name, req.Credential)
	if err != nil {
		fail(ctx, err)
		return
	}
	ok(ctx, registerFinishResp{Credential: toCredentialView(cred), RedirectURL: redirect})
}

func (c *Connector) bindBegin(ctx *gin.Context) {
	uid, authed := authUser(ctx)
	if !authed {
		return
	}
	var req bindBeginReq
	if err := decode(ctx, &req); err != nil {
		fail(ctx, err)
		return
	}
	cer, err := c.svc.Load().BeginBind(ctx.Request.Context(), uid, req.State)
	if err != nil {
		fail(ctx, err)
		return
	}
	ok(ctx, assertionResp{Session: cer.Session, Options: cer.Options})
}

func (c *Connector) bindFinish(ctx *gin.Context) {
	uid, authed := authUser(ctx)
	if !authed {
		return
	}
	var req finishReq
	if err := decodeFinish(ctx, &req.Session, &req.Credential, &req); err != nil {
		fail(ctx, err)
		return
	}
	redirect, err := c.svc.Load().FinishBind(ctx.Request.Context(), uid, req.Session, req.Credential)
	if err != nil {
		fail(ctx, err)
		return
	}
	ok(ctx, redirectResp{RedirectURL: redirect})
}

func (c *Connector) listCredentials(ctx *gin.Context) {
	uid, authed := authUser(ctx)
	if !authed {
		return
	}
	creds, err := c.svc.Load().Credentials(ctx.Request.Context(), uid)
	if err != nil {
		fail(ctx, err)
		return
	}
	views := make([]credentialView, 0, len(creds))
	for _, cred := range creds {
		views = append(views, toCredentialView(cred))
	}
	ok(ctx, credentialsResp{Credentials: views})
}

func (c *Connector) renameCredential(ctx *gin.Context) {
	uid, authed := authUser(ctx)
	if !authed {
		return
	}
	id, err := pathID(ctx)
	if err != nil {
		fail(ctx, err)
		return
	}
	var req renameReq
	if err := decode(ctx, &req); err != nil {
		fail(ctx, err)
		return
	}
	cred, err := c.svc.Load().RenameCredential(ctx.Request.Context(), uid, id, req.Name)
	if err != nil {
		fail(ctx, err)
		return
	}
	ok(ctx, credentialResp{Credential: toCredentialView(cred)})
}

func (c *Connector) deleteCredential(ctx *gin.Context) {
	uid, authed := authUser(ctx)
	if !authed {
		return
	}
	id, err := pathID(ctx)
	if err != nil {
		fail(ctx, err)
		return
	}
	if err := c.svc.Load().DeleteCredential(ctx.Request.Context(), uid, id); err != nil {
		fail(ctx, err)
		return
	}
	ok(ctx, nil)
}
