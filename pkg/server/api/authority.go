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

package api

import (
	"bytes"
	"net/http"

	"golang.org/x/crypto/ssh"
)

func (c *Api) Authority(w http.ResponseWriter, r *http.Request) {
	if !clientAuthenticated(r) {
		http.Error(w, "no client certificate provided", http.StatusUnauthorized)
		return
	}

	var buffer bytes.Buffer
	for _, entry := range c.conf.ExtraAuthorities {
		buffer.WriteString("@cert-authority * ")
		buffer.WriteString(entry)
		buffer.WriteRune('\n')
	}

	buffer.WriteString("@cert-authority * ")
	buffer.Write(ssh.MarshalAuthorizedKey(c.signer.PublicKey()))

	_, _ = w.Write(buffer.Bytes())
}
