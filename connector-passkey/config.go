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
	"strings"

	"github.com/apache/answer-plugins/connector-passkey-v2/i18n"
	"github.com/apache/answer/plugin"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// PasskeyConfig holds the admin configuration for this plugin.
type PasskeyConfig struct {
	RPName          string `json:"rp_name"`
	RPID            string `json:"rp_id"`
	RPOrigins       string `json:"rp_origins"`
	AttestationType string `json:"attestation_type"`
}

func (c *Connector) ConfigFields() []plugin.ConfigField {
	return []plugin.ConfigField{
		{
			Name:        "rp_name",
			Type:        plugin.ConfigTypeInput,
			Title:       plugin.MakeTranslator(i18n.ConfigRPName),
			Description: plugin.MakeTranslator(i18n.ConfigRPNameDesc),
			Required:    true,
			Value:       c.Config.RPName,
			UIOptions: plugin.ConfigFieldUIOptions{
				InputType: plugin.InputTypeText,
			},
		},
		{
			Name:        "rp_id",
			Type:        plugin.ConfigTypeInput,
			Title:       plugin.MakeTranslator(i18n.ConfigRPID),
			Description: plugin.MakeTranslator(i18n.ConfigRPIDDesc),
			Required:    true,
			Value:       c.Config.RPID,
			UIOptions: plugin.ConfigFieldUIOptions{
				InputType: plugin.InputTypeText,
			},
		},
		{
			Name:        "rp_origins",
			Type:        plugin.ConfigTypeInput,
			Title:       plugin.MakeTranslator(i18n.ConfigRPOrigins),
			Description: plugin.MakeTranslator(i18n.ConfigRPOriginsDesc),
			Required:    true,
			Value:       c.Config.RPOrigins,
			UIOptions: plugin.ConfigFieldUIOptions{
				InputType: plugin.InputTypeText,
			},
		},
		{
			Name:        "attestation_type",
			Type:        plugin.ConfigTypeSelect,
			Title:       plugin.MakeTranslator(i18n.ConfigAttestation),
			Description: plugin.MakeTranslator(i18n.ConfigAttestationDesc),
			Required:    false,
			Value:       c.Config.AttestationType,
			Options: []plugin.ConfigFieldOption{
				{Label: plugin.MakeTranslator(i18n.ConfigAttestationNone), Value: "none"},
				{Label: plugin.MakeTranslator(i18n.ConfigAttestationIndirect), Value: "indirect"},
				{Label: plugin.MakeTranslator(i18n.ConfigAttestationDirect), Value: "direct"},
			},
		},
	}
}

func (c *Connector) ConfigReceiver(config []byte) error {
	var cfg PasskeyConfig
	if err := json.Unmarshal(config, &cfg); err != nil {
		return fmt.Errorf("failed to parse passkey config: %w", err)
	}

	if cfg.AttestationType == "" {
		cfg.AttestationType = "none"
	}

	c.Config = cfg

	if cfg.RPName == "" || cfg.RPID == "" || cfg.RPOrigins == "" {
		return nil
	}

	origins := parseOrigins(cfg.RPOrigins)
	attestation := protocol.ConveyancePreference(cfg.AttestationType)

	wconfig := &webauthn.Config{
		RPDisplayName: cfg.RPName,
		RPID:          cfg.RPID,
		RPOrigins:     origins,
		AttestationPreference: attestation,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			AuthenticatorAttachment: "",
			ResidentKey:             protocol.ResidentKeyRequirementRequired,
			UserVerification:        protocol.VerificationRequired,
		},
	}

	w, err := webauthn.New(wconfig)
	if err != nil {
		return fmt.Errorf("failed to initialize WebAuthn: %w", err)
	}

	c.mu.Lock()
	c.WebAuthn = w
	c.mu.Unlock()

	return nil
}

func parseOrigins(raw string) []string {
	parts := strings.Split(raw, ",")
	origins := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			origins = append(origins, p)
		}
	}
	return origins
}
