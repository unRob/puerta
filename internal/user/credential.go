// SPDX-License-Identifier: Apache-2.0
// Copyright © 2022 Roberto Hidalgo <nidito@un.rob.mx>
package user

import (
	"encoding/json"

	"github.com/go-webauthn/webauthn/webauthn"
)

type Credential struct {
	UserID int    `db:"user"`
	Data   string `db:"data"`
	wan    *webauthn.Credential
}

func (c *Credential) AsWebAuthn() webauthn.Credential {
	if c.wan == nil {
		c.wan = &webauthn.Credential{}
		if err := json.Unmarshal([]byte(c.Data), &c.wan); err != nil {
			panic(err)
		}
	}
	return *c.wan
}
