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

// Package rp holds the WebAuthn relying-party configuration: it normalizes and
// validates the admin settings, fills in defaults derived from the Answer Site
// URL and builds the *webauthn.WebAuthn instance used by the ceremonies.
package rp

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// CeremonyTimeout is the client timeout of every ceremony. The server enforces
// it too (webauthn Timeouts.Enforce), and the sealed ceremony session uses the
// same lifetime.
const CeremonyTimeout = 5 * time.Minute

// ErrNotConfigured is returned by Resolve when no usable relying-party settings
// can be derived from the admin configuration and the Site URL.
var ErrNotConfigured = errors.New("passkey relying party is not configured")

// Config is the admin configuration as stored by Answer. The JSON keys are the
// plugin config field names.
type Config struct {
	Name    string `json:"rp_name"`
	ID      string `json:"rp_id"`
	Origins string `json:"rp_origins"`
}

// Settings are resolved, validated relying-party settings.
type Settings struct {
	Name    string
	ID      string
	Origins []string
}

// Normalize trims surrounding white space from every field and lowercases the
// RP ID.
func (c *Config) Normalize() {
	c.Name = strings.TrimSpace(c.Name)
	c.ID = strings.ToLower(strings.TrimSpace(c.ID))
	c.Origins = strings.TrimSpace(c.Origins)
}

// Validate checks the explicitly configured values. When siteURL is usable the
// fully resolved settings (explicit values plus Site URL defaults) are checked;
// otherwise the checks that depend on the Site URL are skipped. A config with
// every field empty is valid as long as the Site URL defaults are.
func (c Config) Validate(siteURL string) error {
	c.Normalize()
	site, _ := parseSiteURL(siteURL)
	if site != nil {
		_, err := c.resolve(site)
		return err
	}
	if c.ID != "" {
		if err := validateID(c.ID); err != nil {
			return err
		}
	}
	origins, err := parseOrigins(c.Origins)
	if err != nil {
		return err
	}
	if c.ID != "" {
		for _, o := range origins {
			if err := checkOriginMatchesID(o, c.ID); err != nil {
				return err
			}
		}
	}
	return nil
}

// Resolve returns the effective settings: explicit values win, empty values
// default to the host name / origin of siteURL. Any failure is reported as an
// error wrapping ErrNotConfigured.
func (c Config) Resolve(siteURL string) (Settings, error) {
	c.Normalize()
	site, err := parseSiteURL(siteURL)
	if err != nil {
		site = nil
	}
	s, err := c.resolve(site)
	if err != nil {
		return Settings{}, fmt.Errorf("%w: %v", ErrNotConfigured, err)
	}
	return s, nil
}

func (c Config) resolve(site *url.URL) (Settings, error) {
	var siteHost, siteOrigin string
	if site != nil {
		siteHost = strings.ToLower(site.Hostname())
		siteOrigin = strings.ToLower(site.Scheme) + "://" + strings.ToLower(site.Host)
	}

	id := c.ID
	if id == "" {
		id = siteHost
	}
	if id == "" {
		return Settings{}, errors.New("no relying party ID configured and no Site URL to derive it from")
	}
	if err := validateID(id); err != nil {
		return Settings{}, err
	}

	origins, err := parseOrigins(c.Origins)
	if err != nil {
		return Settings{}, err
	}
	if len(origins) == 0 && siteOrigin != "" {
		o, err := normalizeOrigin(siteOrigin)
		if err != nil {
			return Settings{}, fmt.Errorf("site URL: %w", err)
		}
		origins = []string{o}
	}
	if len(origins) == 0 {
		return Settings{}, errors.New("no allowed origins configured and no Site URL to derive them from")
	}
	for _, o := range origins {
		if err := checkOriginMatchesID(o, id); err != nil {
			return Settings{}, err
		}
	}

	name := c.Name
	if name == "" {
		name = siteHost
	}
	if name == "" {
		name = id
	}
	return Settings{Name: name, ID: id, Origins: origins}, nil
}

// WebAuthn builds the relying party. Resident keys and user verification are
// required, attestation is not requested and ceremony timeouts are enforced by
// the server.
func (s Settings) WebAuthn() (*webauthn.WebAuthn, error) {
	timeout := webauthn.TimeoutConfig{Enforce: true, Timeout: CeremonyTimeout, TimeoutUVD: CeremonyTimeout}
	w, err := webauthn.New(&webauthn.Config{
		RPID:                  s.ID,
		RPDisplayName:         s.Name,
		RPOrigins:             append([]string(nil), s.Origins...),
		AttestationPreference: protocol.PreferNoAttestation,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			ResidentKey:        protocol.ResidentKeyRequirementRequired,
			RequireResidentKey: protocol.ResidentKeyRequired(),
			UserVerification:   protocol.VerificationRequired,
		},
		Timeouts: webauthn.TimeoutsConfig{Login: timeout, Registration: timeout},
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNotConfigured, err)
	}
	return w, nil
}

// parseSiteURL returns nil, nil for an empty Site URL.
func parseSiteURL(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return nil, fmt.Errorf("site URL %q is not an absolute http(s) URL", raw)
	}
	return u, nil
}

// parseOrigins splits a comma- or newline-separated list, normalizes each
// entry and removes duplicates while keeping the input order.
func parseOrigins(raw string) ([]string, error) {
	parts := strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == '\n' || r == '\r' })
	origins := make([]string, 0, len(parts))
	seen := make(map[string]bool, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		o, err := normalizeOrigin(p)
		if err != nil {
			return nil, err
		}
		if !seen[o] {
			seen[o] = true
			origins = append(origins, o)
		}
	}
	return origins, nil
}

// normalizeOrigin accepts scheme://host[:port] with an optional trailing
// slash and returns it lowercased, without a default port.
func normalizeOrigin(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("origin %q is not a valid URL", raw)
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	switch {
	case u.Opaque != "" || host == "":
		return "", fmt.Errorf("origin %q must look like https://example.com", raw)
	case u.User != nil:
		return "", fmt.Errorf("origin %q must not contain user information", raw)
	case u.Path != "" && u.Path != "/":
		return "", fmt.Errorf("origin %q must not contain a path", raw)
	case u.RawQuery != "" || u.ForceQuery || u.Fragment != "":
		return "", fmt.Errorf("origin %q must not contain a query or fragment", raw)
	case scheme == "https":
	case scheme == "http" && host == "localhost":
	case scheme == "http":
		return "", fmt.Errorf("origin %q must use https (http is only allowed for localhost)", raw)
	default:
		return "", fmt.Errorf("origin %q must use https", raw)
	}
	port := u.Port()
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	if port != "" {
		return scheme + "://" + net.JoinHostPort(host, port), nil
	}
	if strings.Contains(host, ":") { // IPv6 literal
		return scheme + "://[" + host + "]", nil
	}
	return scheme + "://" + host, nil
}

func checkOriginMatchesID(origin, id string) error {
	u, err := url.Parse(origin)
	if err != nil {
		return fmt.Errorf("origin %q is not a valid URL", origin)
	}
	host := strings.ToLower(u.Hostname())
	if host != id && !strings.HasSuffix(host, "."+id) {
		return fmt.Errorf("origin %q is not on the relying party ID %q or one of its subdomains", origin, id)
	}
	return nil
}

// validateID accepts "localhost" or a lowercase domain name. Schemes, ports,
// paths and IP literals are rejected.
func validateID(id string) error {
	if strings.Contains(id, "://") || strings.ContainsAny(id, "/:?#@[] ") {
		return fmt.Errorf("relying party ID %q must be a bare domain such as example.com (no scheme, port or path)", id)
	}
	if net.ParseIP(id) != nil {
		return fmt.Errorf("relying party ID %q must be a domain name, not an IP address", id)
	}
	if id != strings.ToLower(id) {
		return fmt.Errorf("relying party ID %q must be lowercase", id)
	}
	if id == "localhost" {
		return nil
	}
	if len(id) > 253 || !strings.Contains(id, ".") {
		return fmt.Errorf("relying party ID %q is not a valid domain name", id)
	}
	for _, label := range strings.Split(id, ".") {
		if !validLabel(label) {
			return fmt.Errorf("relying party ID %q is not a valid domain name", id)
		}
	}
	return nil
}

func validLabel(label string) bool {
	if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for _, r := range label {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
			return false
		}
	}
	return true
}
