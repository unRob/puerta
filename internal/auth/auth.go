// SPDX-License-Identifier: Apache-2.0
// Copyright © 2022 Roberto Hidalgo <nidito@un.rob.mx>
package auth

import (
	"fmt"
	"net/http"
	"time"

	"github.com/alexedwards/scs/v2"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/julienschmidt/httprouter"
	"github.com/sirupsen/logrus"
	"github.com/upper/db/v4"
)

type AuthContext string

const (
	ContextCookieName AuthContext = "_puerta"
	ContextUser       AuthContext = "_user"
)

type Manager struct {
	db   db.Session
	wan  *webauthn.WebAuthn
	sess *scs.SessionManager
}

func NewManager(wan *webauthn.WebAuthn, db db.Session) *Manager {
	sessionManager := scs.New()
	sessionManager.Lifetime = 5 * time.Minute
	return &Manager{
		db:   db,
		wan:  wan,
		sess: sessionManager,
	}
}

func (am *Manager) Route(router http.Handler) http.Handler {
	return am.sess.LoadAndSave(router)
}

func (am *Manager) requestAuth(w http.ResponseWriter, status int) {
	http.Error(w, http.StatusText(status), status)
}

func (am *Manager) NewSession(w http.ResponseWriter, req *http.Request, ps httprouter.Params) {
	err := req.ParseForm()
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	username := req.FormValue("user")
	password := req.FormValue("password")

	user := &User{}
	if err := am.db.Get(user, db.Cond{"name": username}); err != nil {
		err := &InvalidCredentials{code: http.StatusForbidden, reason: fmt.Sprintf("User not found for name: %s (%s)", username, err)}
		err.Log()
		http.Error(w, err.Error(), err.Code())
		return
	}

	if err := user.Login(password); err != nil {
		code := http.StatusBadRequest
		status := http.StatusText(code)
		if err, ok := err.(InvalidCredentials); ok {
			code = err.Code()
			status = err.Error()
			err.Log()
		}
		http.Error(w, status, code)
		return
	}

	sess, err := NewSession(user, am.db.Collection("session"))
	if err != nil {
		http.Error(w, fmt.Sprintf("Could not create a session: %s", err), http.StatusInternalServerError)
		return
	}

	w.Header().Add("Set-Cookie", fmt.Sprintf("%s=%s; Max-Age=%d; Path=/;", ContextCookieName, sess.Token, user.TTL.Seconds()))

	logrus.Infof("Created session for %s", user.Name)

	if req.FormValue("async") == "true" {
		w.Write([]byte(user.Greeting))
	} else {
		http.Redirect(w, req, "/", http.StatusSeeOther)
	}
}
