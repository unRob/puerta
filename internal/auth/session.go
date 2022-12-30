// SPDX-License-Identifier: Apache-2.0
// Copyright © 2022 Roberto Hidalgo <nidito@un.rob.mx>
package auth

import (
	"math/rand"
	"strings"
	"time"

	"github.com/upper/db/v4"
)

var letterSrc = rand.NewSource(time.Now().UnixNano())

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const (
	// 6 bits to represent a letter index
	letterIdxBits = 6
	// All 1-bits, as many as letterIdxBits
	letterIdxMask = 1<<letterIdxBits - 1
	// # of letter indices fitting in 63 bits
	letterIdxMax = 63 / letterIdxBits
)

func NewToken() string {
	sb := strings.Builder{}
	n := 32
	sb.Grow(n)

	for i, cache, remain := n-1, letterSrc.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = letterSrc.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			sb.WriteByte(letterBytes[idx])
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	return sb.String()
}

type Session struct {
	Token   string    `db:"token"`
	UserID  int       `db:"user"`
	Expires time.Time `db:"expires"`
}

type SessionUser struct {
	Token   string    `db:"token"`
	UserID  int       `db:"user"`
	Expires time.Time `db:"expires"`
	User    `db:",inline"`
}

func (s *Session) Store(sess db.Session) db.Store {
	return sess.Collection("session")
}

func (s *Session) Expired() bool {
	return s.Expires.Before(time.Now())
}

func NewSession(user *User, table db.Collection) (*Session, error) {
	sess := &Session{
		Token:   NewToken(),
		UserID:  user.ID,
		Expires: user.TTL.FromNow(),
	}

	// delete previous sessions
	table.Find(db.Cond{"user": user.ID}).Delete()
	// insert new one
	_, err := table.Insert(sess)
	return sess, err
}
