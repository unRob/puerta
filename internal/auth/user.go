// SPDX-License-Identifier: Apache-2.0
// Copyright © 2022 Roberto Hidalgo <nidito@un.rob.mx>
package auth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/sirupsen/logrus"
	"github.com/upper/db/v4"
	"golang.org/x/crypto/bcrypt"
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

func UserFromContext(req *http.Request) *User {
	u := req.Context().Value(ContextUser)

	if u != nil {
		return u.(*User)
	}
	return nil
}

type User struct {
	ID          int           `db:"id" json:"-"`
	Handle      string        `db:"user" json:"user"`
	Name        string        `db:"name" json:"name"`
	Password    string        `db:"password" json:"password"`
	Schedule    *UserSchedule `db:"schedule,omitempty" json:"schedule"`
	Expires     *time.Time    `db:"expires,omitempty" json:"expires"`
	Greeting    string        `db:"greeting" json:"greeting"`
	TTL         *TTL          `db:"max_ttl,omitempty" json:"max_ttl"`
	Require2FA  bool          `db:"second_factor" json:"second_factor"`
	IsAdmin     bool          `db:"is_admin" json:"admin"`
	credentials []*Credential
}

func (u *User) WebAuthnID() []byte {
	return []byte(fmt.Sprintf("%d", u.ID))
}

// User Name according to the Relying Party
func (u *User) WebAuthnName() string {
	return u.Handle
}

// Display Name of the user
func (u *User) WebAuthnDisplayName() string {
	return u.Name
}

// User's icon url
func (u *User) WebAuthnIcon() string {
	return ""
}

// Credentials owned by the user
func (u *User) WebAuthnCredentials() []webauthn.Credential {
	res := []webauthn.Credential{}
	if u.credentials != nil {
		for _, c := range u.credentials {
			res = append(res, c.AsWebAuthn())
		}
	}
	return res
}

func (u *User) Store(sess db.Session) db.Store {
	return sess.Collection("user")
}

func (u *User) FetchCredentials(sess db.Session) error {
	creds := []*Credential{}
	err := sess.Collection("credential").Find(db.Cond{"user": u.ID}).All(&creds)
	if err != nil {
		logrus.Errorf("could not fetch credentials: %s", err)
		return err
	}
	u.credentials = creds
	logrus.Debugf("fetched %d credentials", len(creds))

	return nil
}

func (o *User) UnmarshalJSON(b []byte) error {
	type alias User
	xo := &alias{TTL: &DefaultTTL}
	if err := json.Unmarshal(b, xo); err != nil {
		return err
	}
	*o = User(*xo)
	return nil
}

func (user *User) Expired() bool {
	return user.Expires != nil && user.Expires.Before(time.Now())
}

func (user *User) IsAllowed(t time.Time) error {
	if user.Expired() {
		return fmt.Errorf("usuario expirado, avísale a Roberto")
	}

	if user.Schedule != nil && !user.Schedule.AllowedAt(time.Now()) {
		return fmt.Errorf("accesso denegado, intente nuevamente en otro momento")
	}

	return nil
}

func (user *User) Login(password string) error {
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		reason := fmt.Sprintf("Incorrect password for %s", user.Name)
		return &InvalidCredentials{code: http.StatusForbidden, reason: reason}
	}

	if user.Expired() {
		reason := fmt.Sprintf("Expired user tried to login: %s", user.Name)
		return &InvalidCredentials{code: http.StatusForbidden, reason: reason}
	}

	return nil
}

var _ = db.Record(&User{})
