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

// Package storetest provides a real plugin KV store on SQLite for tests,
// set up like the Answer core does it.
package storetest

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/apache/answer-plugins/connector-passkey/internal/store"
	"github.com/apache/answer/plugin"
	memcache "github.com/segmentfault/pacman/contrib/cache/memory"
	_ "modernc.org/sqlite" // SQLite driver for xorm
	"xorm.io/xorm"
)

// NewSQLiteKV returns a plugin KV operator on a fresh SQLite database in a
// test directory, set up like the Answer core does it: the core
// plugin_kv_storage table, a single open connection and the operator cache
// disabled (as the plugin adapter does). The engine gives raw access to the
// table. Both are closed when the test ends.
func NewSQLiteKV(t testing.TB, pluginSlug string) (*plugin.KVOperator, *xorm.Engine) {
	t.Helper()
	engine, err := xorm.NewEngine("sqlite", filepath.Join(t.TempDir(), "kv.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = engine.Close() })
	engine.SetMaxOpenConns(1) // as the Answer core does for SQLite
	// Equivalent of the core entity.PluginKVStorage table.
	if _, err := engine.Exec(`CREATE TABLE plugin_kv_storage (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		plugin_slug_name VARCHAR(128) NOT NULL,
		"group" VARCHAR(128) NOT NULL,
		"key" VARCHAR(128) NOT NULL,
		value TEXT NOT NULL,
		UNIQUE(plugin_slug_name, "group", "key"))`); err != nil {
		t.Fatal(err)
	}
	op := plugin.NewKVOperator(engine, memcache.NewCache(), pluginSlug)
	op.Option(plugin.WithCacheTTL(-1))
	return op, engine
}

// Store is the KV store.Store on SQLite, with raw row access for tests.
type Store struct {
	store.Store
	t  testing.TB
	op *plugin.KVOperator
}

// NewStore returns a Store on a fresh SQLite-backed KV operator.
func NewStore(t testing.TB) *Store {
	t.Helper()
	op, _ := NewSQLiteKV(t, "passkey_connector")
	return &Store{Store: store.NewKV(op), t: t, op: op}
}

// DeleteRow deletes one raw KV row, for example to simulate a concurrent
// change between two calls.
func (s *Store) DeleteRow(group, key string) {
	if err := s.op.Del(context.Background(), plugin.KVParams{Group: group, Key: key}); err != nil {
		s.t.Fatal(err)
	}
}
