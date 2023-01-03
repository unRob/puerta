// SPDX-License-Identifier: Apache-2.0
// Copyright © 2022 Roberto Hidalgo <nidito@un.rob.mx>
package auth

import (
	"context"
	"fmt"
	"net/http"

	"github.com/julienschmidt/httprouter"
	"github.com/sirupsen/logrus"
	"github.com/upper/db/v4"
)

func (am *Manager) withUser(handler httprouter.Handle) httprouter.Handle {
	return func(w http.ResponseWriter, req *http.Request, ps httprouter.Params) {
		ctxUser := req.Context().Value(ContextUser)
		req = func() *http.Request {
			if ctxUser != nil {
				return req
			}

			cookie, err := req.Cookie(string(ContextCookieName))
			if err != nil {
				logrus.Debugf("no cookie for user found in jar <%s>", req.Cookies())
				return req
			}

			session := &SessionUser{}
			q := am.db.SQL().
				Select("s.token as token, ", "u.*").
				From("session as s").
				Join("user as u").On("s.user = u.id").
				Where(db.Cond{"s.token": cookie.Value})

			if err := q.One(&session); err != nil {
				logrus.Debugf("no cookie found in DB for jar <%s>: %s", req.Cookies(), err)
				w.Header().Add("Set-Cookie", fmt.Sprintf("%s=%s; Max-Age=%d; Secure; Path=/;", ContextCookieName, "", -1))
				return req
			}

			if session.Expired() {
				logrus.Debugf("expired cookie found in DB for jar <%s>", req.Cookies())
				w.Header().Add("Set-Cookie", fmt.Sprintf("%s=%s; Max-Age=%d; Secure; Path=/;", ContextCookieName, "", -1))
				err := am.db.Collection("session").Find(db.Cond{"token": cookie.Value}).Delete()
				if err != nil {
					logrus.Errorf("could not purge expired session from DB: %s", err)
				}
				return req
			}

			return req.WithContext(context.WithValue(req.Context(), ContextUser, &session.User))
		}()

		handler(w, req, ps)
	}
}

func (am *Manager) RequireAuth(handler httprouter.Handle) httprouter.Handle {
	return am.withUser(func(w http.ResponseWriter, req *http.Request, ps httprouter.Params) {
		if req.Context().Value(ContextUser) == nil {
			am.requestAuth(w, http.StatusUnauthorized)
			return
		}

		handler(w, req, ps)
	})
}

func (am *Manager) RequireAuthOrRedirect(handler httprouter.Handle, target string) httprouter.Handle {
	return am.withUser(func(w http.ResponseWriter, req *http.Request, ps httprouter.Params) {
		if req.Context().Value(ContextUser) == nil {
			http.Redirect(w, req, target, http.StatusTemporaryRedirect)
			return
		}

		handler(w, req, ps)
	})
}

func (am *Manager) RegisterSecondFactor() httprouter.Handle {
	return am.RequireAuth(func(w http.ResponseWriter, req *http.Request, ps httprouter.Params) {
		user := req.Context().Value(ContextUser).(*User)
		if !user.Require2FA {
			http.Error(w, http.StatusText(http.StatusConflict), http.StatusConflict)
			return
		}

		err := am.WebAuthnFinishRegistration(req)
		if err != nil {
			logrus.Errorf("Failed during webauthn flow: %s", err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

	})
}

func (am *Manager) Enforce2FA(handler httprouter.Handle) httprouter.Handle {
	return am.RequireAuth(func(w http.ResponseWriter, req *http.Request, ps httprouter.Params) {
		user := req.Context().Value(ContextUser).(*User)
		if !user.Require2FA {
			handler(w, req, ps)
			return
		}

		logrus.Debug("Enforcing 2fa for request")
		var err error
		err = user.FetchCredentials(am.db)
		if err != nil {
			logrus.Errorf("Failed fetching credentials: %s", err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		if len(user.credentials) == 0 {
			err = am.WebAuthnBeginRegistration(req)
		} else {
			err = am.WebAuthnLogin(req)
		}

		if err != nil {
			if wafc, ok := err.(WebAuthFlowChallenge); ok {
				w.WriteHeader(200)
				w.Header().Add("content-type", "application/json")
				w.Header().Add("webauthn", wafc.Header())
				return
			}

			logrus.Errorf("Failed during webauthn flow: %s", err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		defer am.sess.RenewToken(req.Context())
		handler(w, req, ps)
	})
}

func (am *Manager) RequireAdmin(handler httprouter.Handle) httprouter.Handle {
	return am.RequireAuth(func(w http.ResponseWriter, req *http.Request, ps httprouter.Params) {
		user := req.Context().Value(ContextUser).(*User)
		if !user.IsAdmin {
			am.requestAuth(w, http.StatusUnauthorized)
			return
		}
		handler(w, req, ps)
	})
}
