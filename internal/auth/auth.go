// SPDX-License-Identifier: Apache-2.0
// Copyright © 2022 Roberto Hidalgo <nidito@un.rob.mx>
package auth

import (
	"fmt"
	"net/http"
	"time"

	"git.rob.mx/nidito/puerta/internal/constants"
	"git.rob.mx/nidito/puerta/internal/errors"
	"git.rob.mx/nidito/puerta/internal/user"
	"github.com/alexedwards/scs/v2"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/julienschmidt/httprouter"
	"github.com/sirupsen/logrus"
	"github.com/upper/db/v4"
)

var _db db.Session
var _wan *webauthn.WebAuthn
var _sess *scs.SessionManager

func Route(wan *webauthn.WebAuthn, db db.Session, router http.Handler) http.Handler {
	_db = db
	_wan = wan
	_sess = scs.New()
	_sess.Lifetime = 5 * time.Minute
	return _sess.LoadAndSave(router)
}

func requestAuth(w http.ResponseWriter, status int) {
	http.Error(w, http.StatusText(status), status)
}

func LoginHandler(w http.ResponseWriter, req *http.Request, ps httprouter.Params) {

	err := req.ParseForm()
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	username := req.FormValue("user")
	password := req.FormValue("password")

	user := &user.User{}
	if err := _db.Get(user, db.Cond{"handle": username}); err != nil {
		err := &errors.InvalidCredentials{Status: http.StatusForbidden, Reason: fmt.Sprintf("User not found for name: %s (%s)", username, err)}
		err.Log()
		http.Error(w, err.Error(), err.Code())
		return
	}

	if err := user.Login(password); err != nil {

		code := http.StatusBadRequest
		status := http.StatusText(code)
		if err, ok := err.(*errors.InvalidCredentials); ok {
			code = err.Code()
			status = err.Error()
			err.Log()
		} else {
			logrus.Errorf("could not login %s: %s", username, err.Error())
		}
		http.Error(w, status, code)
		return
	}

	sess, err := NewSession(user, _db.Collection("session"))
	if err != nil {
		err = fmt.Errorf("Could not create a session: %s", err)
		logrus.Error(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Add("Set-Cookie", fmt.Sprintf("%s=%s; Max-Age=%d; Path=/;", constants.ContextCookieName, sess.Token, user.TTL.Seconds()))

	logrus.Infof("Created session for %s", user.Name)

	if req.FormValue("async") == "true" {
		w.Write([]byte(user.Greeting))
	} else {
		http.Redirect(w, req, "/", http.StatusSeeOther)
	}
}
