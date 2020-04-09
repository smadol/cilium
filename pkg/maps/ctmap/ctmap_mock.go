// Copyright 2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ctmap

import (
	"github.com/cilium/cilium/pkg/bpf"
)

// A "Record" designates a map entry (key + value), but avoid "entry" because of
// possible confusion with "CtEntry" (actually the value part).
type ctMockMapRecord struct {
	key   CtKey
	value CtEntry
}

// CtMockMap implements the CtMap interface and can be used for unit tests.
type CtMockMap struct {
	entries []*ctMockMapRecord
}

// NewCtMockMap is a constructor for a CtMockMap.
func NewCtMockMap() *CtMockMap {
	m := &CtMockMap{}
	m.entries = make([]*ctMockMapRecord, 0)
	return m
}

// Open does nothing, mock maps need not be opened.
func (m *CtMockMap) Open() error {
	return nil
}

// Close does nothing, mock maps need not be closed either.
func (m *CtMockMap) Close() error {
	return nil
}

// Path returns a mock path for the mock map.
func (m *CtMockMap) Path() (string, error) {
	return "/this/is/a/mock/map", nil
}

// DumpEntries iterates through Map m and writes the values of the ct entries
// in m to a string.
func (m *CtMockMap) DumpEntries() (string, error) {
	return doDumpEntries(m)
}

// DumpWithCallback runs the callback on each entry of the mock map.
func (m *CtMockMap) DumpWithCallback(cb bpf.DumpCallback) error {
	if cb == nil {
		return nil
	}
	for _, e := range m.entries {
		if e != nil {
			cb(e.key, &e.value)
		}
	}
	return nil
}

// InsertRecord adds a new entry to the mock map.
func (m *CtMockMap) InsertRecord(key CtKey, val CtEntry) {
	entry := ctMockMapRecord{key: key, value: val}
	m.entries = append(m.entries, &entry)
}
