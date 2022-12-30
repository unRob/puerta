// SPDX-License-Identifier: Apache-2.0
// Copyright © 2022 Roberto Hidalgo <nidito@un.rob.mx>
package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"git.rob.mx/nidito/puerta/internal/door"
	"github.com/alexedwards/scs/v2"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/julienschmidt/httprouter"
	"github.com/sirupsen/logrus"
	"github.com/upper/db/v4"
)

type AuthContext string

const (
	ContextCookieName  AuthContext = "_puerta"
	ContextSessionName AuthContext = "_rex"
	ContextUserName    AuthContext = "auth-username"
	ContextGreeting    AuthContext = "auth-greeting"
	ContextDoor        AuthContext = "auth-door"
)

type Manager struct {
	db   db.Session
	door door.Door
	wan  *webauthn.WebAuthn
	sess *scs.SessionManager
}

func NewManager(wan *webauthn.WebAuthn, door door.Door, db db.Session) *Manager {
	sessionManager := scs.New()
	sessionManager.Lifetime = 5 * time.Minute
	return &Manager{
		door: door,
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

func (am *Manager) Protected(handler httprouter.Handle, redirect, enforce2FA bool) httprouter.Handle {

	return func(w http.ResponseWriter, req *http.Request, ps httprouter.Params) {
		ctx := req.Context()
		var user *User
		if ctxUser := ctx.Value(ContextUserName); ctxUser == nil {
			cookie, err := req.Cookie(string(ContextCookieName))

			if err != nil {
				logrus.Debugf("no cookie value found in <%s>", req.Cookies())
				if redirect {
					http.Redirect(w, req, "/login", http.StatusTemporaryRedirect)
				} else {
					am.requestAuth(w, http.StatusUnauthorized)
				}
				return
			}

			q := am.db.SQL().
				Select("s.token as token, ", "u.*").
				From("session as s").
				Join("user as u").On("s.user = u.id").
				Where(db.Cond{"s.token": cookie.Value})

			session := &SessionUser{}
			if err := q.One(&session); err != nil {
				w.Header().Add("Set-Cookie", fmt.Sprintf("%s=%s; Max-Age=%d; Secure; Path=/;", ContextCookieName, "", -1))
				if redirect {
					http.Redirect(w, req, "/login", http.StatusSeeOther)
				} else {
					am.requestAuth(w, http.StatusUnauthorized)
				}
				return
			}

			if err := session.User.IsAllowed(time.Now()); err != nil {
				logrus.Errorf("Denying access to %s: %s", session.User.Name, err)
				am.requestAuth(w, http.StatusForbidden)
				return
			}

			req = req.WithContext(context.WithValue(ctx, ContextUserName, session.User.Name))
			req = req.WithContext(context.WithValue(req.Context(), ContextGreeting, session.User.Greeting))
			req = req.WithContext(context.WithValue(req.Context(), ContextDoor, am.door))
			logrus.Debug("found allowed user")
			user = &session.User
		}

		if enforce2FA && user.Require2FA {
			logrus.Debug("Enforcing 2fa for request")
			var err error
			err = user.FetchCredentials(am.db)
			if err != nil {
				logrus.Errorf("Failed fetching credentials: %s", err.Error())
				w.WriteHeader(http.StatusInternalServerError)
			}

			if len(user.credentials) == 0 {
				err = am.WebAuthnRegister(user, req)
			} else {
				err = am.WebAuthnLogin(user, req)
			}

			if err != nil {
				if wafc, ok := err.(WebAuthFlowChallenge); ok {
					logrus.Debugf("Issuing challenge")
					w.WriteHeader(200)
					w.Header().Add("content-type", "application/json")
					w.Write([]byte(wafc.Error()))
					logrus.Debugf("Issued challenge")
					return
				}

				logrus.Errorf("Failed during webauthn flow: %s", err.Error())
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
		}
		handler(w, req, ps)
	}
}

func (am *Manager) WebAuthnRegister(user *User, req *http.Request) error {
	sd := am.sess.GetBytes(req.Context(), "wan-register")
	if sd == nil {
		logrus.Infof("Starting webauthn registration for %s", user.Name)
		options, sessionData, err := am.wan.BeginRegistration(user)
		if err != nil {
			err = fmt.Errorf("error starting webauthn: %s", err)
			logrus.Error(err)
			return err
		}

		var b bytes.Buffer
		if err := json.NewEncoder(&b).Encode(&sessionData); err != nil {
			return err
		}

		am.sess.Put(req.Context(), "wan-register", b.Bytes())

		return WebAuthFlowChallenge{"register", &options}
	}

	var sessionData webauthn.SessionData
	err := json.Unmarshal(sd, &sessionData)
	if err != nil {
		return err
	}

	cred, err := am.wan.FinishRegistration(user, sessionData, req)
	if err != nil {
		return fmt.Errorf("error finishing webauthn registration: %s", err)
	}

	data, err := json.Marshal(cred)
	if err != nil {
		return fmt.Errorf("error encoding webauthn credential for storage: %s", err)
	}
	credential := &Credential{
		UserID: user.ID,
		Data:   string(data),
	}

	_, err = am.db.Collection("credential").Insert(credential)
	return err
}

func (am *Manager) WebAuthnLogin(user *User, req *http.Request) error {
	sd := am.sess.GetBytes(req.Context(), "rex")
	if sd == nil {
		logrus.Infof("Starting webauthn login flow for %s", user.Name)

		options, sessionData, err := am.wan.BeginLogin(user)
		if err != nil {
			return fmt.Errorf("error starting webauthn login: %s", err)
		}

		var b bytes.Buffer
		if err := json.NewEncoder(&b).Encode(&sessionData); err != nil {
			return fmt.Errorf("could not encode json: %s", err)
		}

		am.sess.Put(req.Context(), "rex", b.Bytes())

		return WebAuthFlowChallenge{"login", &options}
	}

	var sessionData webauthn.SessionData
	err := json.Unmarshal(sd, &sessionData)
	if err != nil {
		return err
	}

	_, err = am.wan.FinishLogin(user, sessionData, req)
	return err
}

func (am *Manager) Cleanup() error {
	return am.db.Collection("session").Find(db.Cond{"Expires": db.Before(time.Now())}).Delete()
}
