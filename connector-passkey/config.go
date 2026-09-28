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
	"encoding/json"
	"fmt"

	"github.com/apache/answer-plugins/connector-passkey/i18n"
	"github.com/apache/answer-plugins/connector-passkey/internal/rp"
	"github.com/apache/answer/plugin"
	"github.com/go-webauthn/webauthn/webauthn"
)

func (c *Connector) ConfigFields() []plugin.ConfigField {
	c.mu.RLock()
	cfg := c.rpConfig
	c.mu.RUnlock()

	field := func(name, value, title, desc string) plugin.ConfigField {
		return plugin.ConfigField{
			Name:        name,
			Type:        plugin.ConfigTypeInput,
			Title:       plugin.MakeTranslator(title),
			Description: plugin.MakeTranslator(desc),
			Required:    false,
			Value:       value,
			UIOptions:   plugin.ConfigFieldUIOptions{InputType: plugin.InputTypeText},
		}
	}
	return []plugin.ConfigField{
		field("rp_name", cfg.Name, i18n.ConfigRPName, i18n.ConfigRPNameDesc),
		field("rp_id", cfg.ID, i18n.ConfigRPID, i18n.ConfigRPIDDesc),
		field("rp_origins", cfg.Origins, i18n.ConfigRPOrigins, i18n.ConfigRPOriginsDesc),
	}
}

// ConfigReceiver receives the settings stored by the core. The core calls
// it in two situations (answer internal/service/plugin_common and
// internal/controller_admin/plugin_controller.go):
//
//   - At start-up, initPluginData passes the row saved in the database, if
//     there is one, and only logs an error. That happens while the core
//     services are constructed, before the HTTP server that mounts the agent
//     routes (RegisterUnAuthRouter and friends) exists: the router depends on
//     the plugin service.
//   - When an admin saves the form, before the core persists it; an error
//     rejects the save. That request needs the HTTP server, so it always
//     comes after the agent routes were mounted.
//
// Before the routes are mounted the settings are therefore what the database
// holds: they are kept even when invalid, so ConfigFields shows them and a
// later save does not overwrite them with blanks, and the error is returned
// for the core to log. At run time relyingParty resolves them per request, so
// invalid settings answer 503 not_configured instead of silently falling
// back to the Site URL defaults. After the routes are mounted invalid
// settings are rejected and the current ones stay in place.
//
// Empty fields default to the Site URL.
func (c *Connector) ConfigReceiver(config []byte) error {
	loading := !c.routesMounted.Load()
	var cfg rp.Config
	if err := json.Unmarshal(config, &cfg); err != nil {
		err = fmt.Errorf("passkey settings are not valid JSON: %w", err)
		if loading {
			c.mu.Lock()
			c.rpConfig, c.rpLoadErr = rp.Config{}, err
			c.mu.Unlock()
		}
		return err
	}
	cfg.Normalize()
	verr := cfg.Validate(plugin.SiteURL())
	if verr != nil && !loading {
		return fmt.Errorf("invalid passkey settings: %w", verr)
	}
	c.mu.Lock()
	c.rpConfig, c.rpLoadErr = cfg, nil
	c.mu.Unlock()
	if verr != nil {
		return fmt.Errorf("stored passkey settings are invalid, passkey sign-in is unavailable until they are fixed: %w", verr)
	}
	return nil
}

// relyingParty resolves the current settings against the Site URL. It fails
// with rp.ErrNotConfigured when they are not usable.
func (c *Connector) relyingParty() (*webauthn.WebAuthn, error) {
	c.mu.RLock()
	cfg, loadErr := c.rpConfig, c.rpLoadErr
	c.mu.RUnlock()

	if loadErr != nil {
		return nil, fmt.Errorf("%w: %v", rp.ErrNotConfigured, loadErr)
	}
	settings, err := cfg.Resolve(plugin.SiteURL())
	if err != nil {
		return nil, err
	}
	return settings.WebAuthn()
}
