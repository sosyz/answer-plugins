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

// Package passkey is the Apache Answer passkey (WebAuthn) connector. This
// package only adapts the Answer plugin interfaces and gin to the gin-free
// ceremony logic in internal/service.
package passkey

import (
	"embed"
	"errors"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/apache/answer-plugins/connector-passkey/i18n"
	"github.com/apache/answer-plugins/connector-passkey/internal/rp"
	"github.com/apache/answer-plugins/connector-passkey/internal/service"
	"github.com/apache/answer-plugins/util"
	"github.com/apache/answer/plugin"
	"github.com/segmentfault/pacman/log"
)

//go:embed info.yaml
var Info embed.FS

const (
	slugName      = "passkey_connector"
	connectorSlug = "passkey"
	pageRoute     = "/connector-passkey-auth"

	// coreAPIPrefix and coreConnectorRedirectPrefix mirror the core
	// commonRouterPrefix and ConnectorRedirectRouterPrefix
	// (internal/controller/connector_controller.go).
	coreAPIPrefix               = "/answer/api/v1"
	coreConnectorRedirectPrefix = "/connector/redirect/"
)

// Connector implements the Answer Connector, Config, UserConfig, Agent and
// KVStorage plugin interfaces.
type Connector struct {
	mu sync.RWMutex
	// rpConfig is the relying-party configuration as stored by the core; see
	// ConfigReceiver.
	rpConfig rp.Config
	// rpLoadErr is set when the stored configuration could not be decoded.
	rpLoadErr error
	// routesMounted is set once the core has mounted the agent routes; see
	// ConfigReceiver.
	routesMounted atomic.Bool
	svc           atomic.Pointer[service.Service]
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
	// Passkey / fingerprint icon, base64-encoded SVG.
	return `PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIyNCIgaGVpZ2h0PSIyNCIgdmlld0JveD0iMCAwIDI0IDI0IiBmaWxsPSJub25lIiBzdHJva2U9ImN1cnJlbnRDb2xvciIgc3Ryb2tlLXdpZHRoPSIyIiBzdHJva2UtbGluZWNhcD0icm91bmQiIHN0cm9rZS1saW5lam9pbj0icm91bmQiPjxwYXRoIGQ9Ik0yIDEyQzIgNi40NzcgNi40NzcgMiAxMiAyYTkuOTYgOS45NiAwIDAgMSA2LjI5IDIuMjEiLz48cGF0aCBkPSJNNyAxMC41YTUgNSAwIDAgMSA3Ljk5LTQiLz48cGF0aCBkPSJNMTIgMTJhMiAyIDAgMCAwLTEuOTggMS43NSIvPjxwYXRoIGQ9Ik0yMiA1LjVsLTQuMiA0LjItMS42LTEuNiIvPjxwYXRoIGQ9Ik04LjUgMTQuNUExNi44NSAxNi44NSAwIDAgMSAyIDE5LjUiLz48cGF0aCBkPSJNMTAuMTcgMTIuNjVBMTEuMTQgMTEuMTQgMCAwIDEgNCAyMSIvPjxwYXRoIGQ9Ik0xNC4zOCAxMy4yOUExNi42OSAxNi42OSAwIDAgMSA2IDIyIi8+PC9zdmc+`
}

func (c *Connector) ConnectorName() plugin.Translator {
	return plugin.MakeTranslator(i18n.ConnectorName)
}

func (c *Connector) ConnectorSlugName() string {
	return connectorSlug
}

// ConnectorSender sends the browser to the plugin page, forwarding the core
// OAuth state. The core ConnectorLogin generates the state and writes it into
// ctx.Request.URL.RawQuery after gin has already cached the query (it called
// ctx.Query("state") first), so ctx.Query would miss it; read the URL
// directly. The core receiver URL is not used: the plugin builds it itself
// after a successful ceremony, so the redirect target never comes from the
// client.
//
// The stale cache also tells the two cases apart: when ctx.Query("state") is
// empty, the caller supplied no state and the core has just generated a
// login-intent state, which gets a state_proof that sign-in requires. A state
// supplied by the caller (a bind state, or one copied from a crafted link)
// gets no proof, so it can never be used for a sign-in ceremony.
func (c *Connector) ConnectorSender(ctx *plugin.GinContext, _ string) (redirectURL string) {
	state := ctx.Request.URL.Query().Get("state")
	query := url.Values{"state": {state}}
	if state != "" && ctx.Query("state") == "" {
		if svc := c.svc.Load(); svc != nil {
			proof, err := svc.LoginStateProof(ctx.Request.Context(), state)
			if err != nil {
				log.Errorf("passkey: login state proof: %v", err)
			} else {
				query.Set("state_proof", proof)
			}
		}
	}
	return pageURL() + "?" + query.Encode()
}

// ConnectorReceiver redeems the one-time token minted by a successful
// ceremony. The token must match the state it was minted for. Only the
// external ID (the WebAuthn user handle) is returned: account linking goes
// through the core bind state, never through user-supplied profile data.
func (c *Connector) ConnectorReceiver(ctx *plugin.GinContext, _ string) (userInfo plugin.ExternalLoginUserInfo, err error) {
	svc := c.svc.Load()
	if svc == nil {
		return userInfo, errors.New("passkey connector is not initialized")
	}
	externalID, err := svc.RedeemLoginToken(ctx.Request.Context(), ctx.Query("token"), ctx.Query("state"))
	if err != nil {
		return userInfo, err
	}
	return plugin.ExternalLoginUserInfo{ExternalID: externalID}, nil
}

// pageURL is the absolute URL of the plugin page (relative when the Site URL
// is not set).
func pageURL() string {
	return strings.TrimRight(plugin.SiteURL(), "/") + pageRoute
}

// receiverURL is the core connector redirect endpoint of this connector, as
// the core builds it for ConnectorSender and ConnectorReceiver (relative
// when the Site URL is not set).
func receiverURL() string {
	return strings.TrimRight(plugin.SiteURL(), "/") + coreAPIPrefix + coreConnectorRedirectPrefix + connectorSlug
}
