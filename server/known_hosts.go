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
	"log"
	"net/http"
)

func (c *context) KnownHosts(w http.ResponseWriter, r *http.Request) {
	log.Print("Returning known_hosts file")
	if !clientAuthenticated(r) {
		http.Error(w, "no client certificate provided", http.StatusUnauthorized)
		return
	}

	hosts, err := c.GetKnownHosts()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write([]byte(hosts))
}

func (c *context) GetKnownHosts() (string, error) {
	var buffer bytes.Buffer
	rows, err := c.db.Query("SELECT * FROM hostkeys")
	if err != nil {
		return "", err
	}
	for rows.Next() {
		var id int
		var hostname, pubkey string
		err = rows.Scan(&id, &hostname, &pubkey)
		if err != nil {
			return "", err
		}
		buffer.WriteString(hostname + " " + pubkey + "\n")
	}
	return buffer.String(), nil
}
