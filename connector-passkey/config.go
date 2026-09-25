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
	"net/url"
	"regexp"
	"strings"

	"github.com/apache/answer-plugins/connector-passkey/i18n"
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

	// Validate all required fields
	if cfg.RPName == "" {
		return fmt.Errorf("RP Name is required")
	}
	if cfg.RPID == "" {
		return fmt.Errorf("RP ID is required")
	}
	if cfg.RPOrigins == "" {
		return fmt.Errorf("at least one origin is required")
	}

	// Validate RP Name length
	if len(cfg.RPName) > 255 {
		return fmt.Errorf("RP Name must be 255 characters or less")
	}

	// Validate RPID format (must be a valid domain)
	if err := validateRPID(cfg.RPID); err != nil {
		return fmt.Errorf("invalid RP ID: %w", err)
	}

	// Parse and validate origins
	origins := parseOrigins(cfg.RPOrigins)
	if len(origins) == 0 {
		return fmt.Errorf("no valid origins provided")
	}
	for _, origin := range origins {
		if err := validateOrigin(origin); err != nil {
			return fmt.Errorf("invalid origin %q: %w", origin, err)
		}
	}

	// Validate attestation type
	validAttestations := map[string]bool{"none": true, "indirect": true, "direct": true}
	if !validAttestations[cfg.AttestationType] {
		return fmt.Errorf("invalid attestation type: must be 'none', 'indirect', or 'direct'")
	}

	c.Config = cfg

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

// validateRPID validates that the RPID is a valid domain name
func validateRPID(rpid string) error {
	if len(rpid) == 0 || len(rpid) > 253 {
		return fmt.Errorf("RPID must be between 1 and 253 characters")
	}

	// Basic domain validation regex
	domainRegex := regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`)
	if !domainRegex.MatchString(rpid) {
		return fmt.Errorf("RPID must be a valid domain name")
	}

	return nil
}

// validateOrigin validates that an origin is a valid URL with http or https scheme
func validateOrigin(origin string) error {
	if len(origin) > 2048 {
		return fmt.Errorf("origin URL must be 2048 characters or less")
	}

	u, err := url.Parse(origin)
	if err != nil {
		return fmt.Errorf("invalid URL format: %w", err)
	}

	if u.Scheme != "https" && u.Scheme != "http" {
		return fmt.Errorf("origin must use http or https scheme")
	}

	if u.Host == "" {
		return fmt.Errorf("origin must include a hostname")
	}

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
