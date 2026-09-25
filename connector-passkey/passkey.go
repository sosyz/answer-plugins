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
	"embed"
	"fmt"
	"sync"

	"github.com/apache/answer-plugins/connector-passkey/i18n"
	"github.com/apache/answer-plugins/util"
	"github.com/apache/answer/plugin"
	"github.com/go-webauthn/webauthn/webauthn"
)

//go:embed  info.yaml
var Info embed.FS

type Connector struct {
	Config    PasskeyConfig
	WebAuthn  *webauthn.WebAuthn
	mu        sync.RWMutex
	kvOperator *plugin.KVOperator
}

func init() {
	plugin.Register(&Connector{})
}

func (c *Connector) Info() plugin.Info {
	info := &util.Info{}
	info.GetInfo(Info)

	return plugin.Info{
		Name:        plugin.MakeTranslator(i18n.InfoName),
		SlugName:    info.SlugName,
		Description: plugin.MakeTranslator(i18n.InfoDescription),
		Author:      info.Author,
		Version:     info.Version,
		Link:        info.Link,
	}
}

func (c *Connector) ConnectorLogoSVG() string {
	// Passkey / fingerprint icon in base64-encoded SVG
	return `PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIyNCIgaGVpZ2h0PSIyNCIgdmlld0JveD0iMCAwIDI0IDI0IiBmaWxsPSJub25lIiBzdHJva2U9ImN1cnJlbnRDb2xvciIgc3Ryb2tlLXdpZHRoPSIyIiBzdHJva2UtbGluZWNhcD0icm91bmQiIHN0cm9rZS1saW5lam9pbj0icm91bmQiPjxwYXRoIGQ9Ik0yIDEyQzIgNi40NzcgNi40NzcgMiAxMiAyYTkuOTYgOS45NiAwIDAgMSA2LjI5IDIuMjEiLz48cGF0aCBkPSJNNyAxMC41YTUgNSAwIDAgMSA3Ljk5LTQiLz48cGF0aCBkPSJNMTIgMTJhMiAyIDAgMCAwLTEuOTggMS43NSIvPjxwYXRoIGQ9Ik0yMiA1LjVsLTQuMiA0LjItMS42LTEuNiIvPjxwYXRoIGQ9Ik04LjUgMTQuNUExNi44NSAxNi44NSAwIDAgMSAyIDE5LjUiLz48cGF0aCBkPSJNMTAuMTcgMTIuNjVBMTEuMTQgMTEuMTQgMCAwIDEgNCAyMSIvPjxwYXRoIGQ9Ik0xNC4zOCAxMy4yOUExNi42OSAxNi42OSAwIDAgMSA2IDIyIi8+PC9zdmc+`
}

func (c *Connector) ConnectorName() plugin.Translator {
	return plugin.MakeTranslator(i18n.ConnectorName)
}

func (c *Connector) ConnectorSlugName() string {
	return "passkey"
}

func (c *Connector) ConnectorSender(ctx *plugin.GinContext, receiverURL string) (redirectURL string) {
	return fmt.Sprintf("/connector-passkey-auth?receiver=%s", receiverURL)
}

func (c *Connector) ConnectorReceiver(ctx *plugin.GinContext, receiverURL string) (userInfo plugin.ExternalLoginUserInfo, err error) {
	token := ctx.Query("token")
	if token == "" {
		return userInfo, fmt.Errorf("missing token parameter")
	}

	tokenData, err := c.consumeToken(ctx, token)
	if err != nil {
		return userInfo, fmt.Errorf("invalid or expired token: %w", err)
	}

	userInfo.ExternalID = tokenData.UserExternalID

	return userInfo, nil
}

func (c *Connector) getWebAuthn() *webauthn.WebAuthn {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.WebAuthn
}
