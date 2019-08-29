/*-
 * Copyright 2016 Square Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package main

import (
	"bytes"
	"net/http"
)

func (c *context) KnownHosts(w http.ResponseWriter, r *http.Request) {
	if !clientAuthenticated(r) {
		http.Error(w, "no client certificate provided", http.StatusUnauthorized)
		return
	}

	hosts, err := c.GetKnownHosts()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_, _ = w.Write([]byte(hosts))
}

func (c *context) GetKnownHosts() (string, error) {
	var buffer bytes.Buffer
	for _, entry := range c.conf.ExtraKnownHosts {
		buffer.WriteString(entry)
		buffer.WriteRune('\n')
	}
	rows, err := c.storage.QueryHostkeys()
	if err != nil {
		return "", err
	}
	for rows.Next() {
		hostname, pubkey, err := rows.Get()
		if err != nil {
			return "", err
		}
		buffer.WriteString(hostname)
		buffer.WriteRune(' ')
		buffer.WriteString(pubkey)
		buffer.WriteRune('\n')
	}
	return buffer.String(), nil
}
