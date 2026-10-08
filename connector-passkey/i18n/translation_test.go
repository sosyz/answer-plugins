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

package i18n

import (
	"os"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

var languages = []string{"en_US.yaml", "zh_CN.yaml"}

func flatten(prefix string, v any, out map[string]string) {
	switch t := v.(type) {
	case map[string]any:
		for k, child := range t {
			key := k
			if prefix != "" {
				key = prefix + "." + k
			}
			flatten(key, child, out)
		}
	default:
		out[prefix] = strings.TrimSpace(toString(t))
	}
}

func toString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func load(t *testing.T, file string) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("%s: %v", file, err)
	}
	out := map[string]string{}
	flatten("", doc, out)
	return out
}

func TestLanguagesHaveSameKeysAndPlaceholders(t *testing.T) {
	placeholder := regexp.MustCompile(`{{\s*\w+\s*}}`)
	base := load(t, languages[0])
	for _, file := range languages[1:] {
		other := load(t, file)
		var missing []string
		for k, v := range base {
			ov, ok := other[k]
			if !ok {
				missing = append(missing, k)
				continue
			}
			a, b := placeholder.FindAllString(v, -1), placeholder.FindAllString(ov, -1)
			sort.Strings(a)
			sort.Strings(b)
			if !reflect.DeepEqual(a, b) {
				t.Errorf("%s: %s placeholders %v, want %v", file, k, b, a)
			}
		}
		for k := range other {
			if _, ok := base[k]; !ok {
				missing = append(missing, "extra "+k)
			}
		}
		if len(missing) > 0 {
			sort.Strings(missing)
			t.Errorf("%s key mismatch: %v", file, missing)
		}
	}
	for k, v := range base {
		if v == "" {
			t.Errorf("empty translation %s", k)
		}
		if strings.Contains(v, "${") {
			t.Errorf("%s uses a ${VAR} placeholder", k)
		}
	}
}

func TestBackendKeysExist(t *testing.T) {
	keys := []string{
		ConnectorName, InfoName, InfoDescription,
		ConfigRPName, ConfigRPNameDesc, ConfigRPID, ConfigRPIDDesc, ConfigRPOrigins, ConfigRPOriginsDesc,
		UserConfigManagePasskeys,
	}
	for _, file := range languages {
		tr := load(t, file)
		for _, k := range keys {
			if tr[k+".other"] == "" {
				t.Errorf("%s: missing %s", file, k)
			}
		}
	}
}
