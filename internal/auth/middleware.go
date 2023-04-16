// SPDX-License-Identifier: Apache-2.0
// Copyright © 2022 Roberto Hidalgo <nidito@un.rob.mx>
package auth

import (
	"context"
	"fmt"
	"net/http"

	"git.rob.mx/nidito/puerta/internal/constants"
	"git.rob.mx/nidito/puerta/internal/errors"
	"git.rob.mx/nidito/puerta/internal/user"
	"github.com/julienschmidt/httprouter"
	"github.com/sirupsen/logrus"
	"github.com/upper/db/v4"
)

func withUser(handler httprouter.Handle) httprouter.Handle {
	return func(w http.ResponseWriter, req *http.Request, ps httprouter.Params) {
		u := user.FromContext(req)
		if u != nil {
			handler(w, req, ps)
			return
		}

		req = func() *http.Request {
			cookie, err := req.Cookie(string(constants.ContextCookieName))
			if err != nil {
				logrus.Debugf("no cookie for user found in jar <%s>", req.Cookies())
				return req
			}

			session := &SessionUser{}
			q := _db.SQL().
				Select("s.token as token, s.expires as expires", "u.*").
				From("session as s").
				Join("user as u").On("s.user = u.id").
				Where(db.Cond{"s.token": cookie.Value})

			if err := q.One(&session); err != nil {
				logrus.Debugf("no cookie found in DB for jar <%s>: %s", req.Cookies(), err)
				w.Header().Add("Set-Cookie", fmt.Sprintf("%s=%s; Max-Age=%d; Secure; Path=/;", constants.ContextCookieName, "", -1))
				return req
			}

			if session.Expired() || session.User.Expired() {
				logrus.Debugf("expired cookie found in DB for jar <%s>", req.Cookies())
				w.Header().Add("Set-Cookie", fmt.Sprintf("%s=%s; Max-Age=%d; Secure; Path=/;", constants.ContextCookieName, "", -1))
				err := _db.Collection("session").Find(db.Cond{"token": cookie.Value}).Delete()
				if err != nil {
					logrus.Errorf("could not purge expired session from DB: %s", err)
				}
				return req
			}

			return req.WithContext(context.WithValue(req.Context(), constants.ContextUser, &session.User))
		}()

		handler(w, req, ps)
	}
}

func RequireAuth(handler httprouter.Handle) httprouter.Handle {
	return withUser(func(w http.ResponseWriter, req *http.Request, ps httprouter.Params) {
		if req.Context().Value(constants.ContextUser) == nil {
			requestAuth(w, http.StatusUnauthorized)
			return
		}

		handler(w, req, ps)
	})
}

func RequireAuthOrRedirect(handler httprouter.Handle, target string) httprouter.Handle {
	return withUser(func(w http.ResponseWriter, req *http.Request, ps httprouter.Params) {
		if req.Context().Value(constants.ContextUser) == nil {
			http.Redirect(w, req, target, http.StatusTemporaryRedirect)
			return
		}

		handler(w, req, ps)
	})
}

func RequireAdminOrRedirect(handler httprouter.Handle, target string) httprouter.Handle {
	return withUser(func(w http.ResponseWriter, req *http.Request, ps httprouter.Params) {
		if req.Context().Value(constants.ContextUser) == nil {
			http.Redirect(w, req, target, http.StatusTemporaryRedirect)
			return
		}

		handler(w, req, ps)
	})
}

func RegisterSecondFactor() httprouter.Handle {
	return RequireAuth(func(w http.ResponseWriter, req *http.Request, ps httprouter.Params) {
		u := user.FromContext(req)
		if !u.Require2FA {
			http.Error(w, http.StatusText(http.StatusConflict), http.StatusConflict)
			return
		}

		err := webAuthnFinishRegistration(req)
		if err != nil {
			logrus.Errorf("Failed during webauthn flow: %s", err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

	})
}

func Enforce2FA(handler httprouter.Handle) httprouter.Handle {
	return RequireAuth(func(w http.ResponseWriter, req *http.Request, ps httprouter.Params) {
		u := user.FromContext(req)
		if !u.Require2FA {
			handler(w, req, ps)
			return
		}

		logrus.Debug("Enforcing 2fa for request")
		if err := u.FetchCredentials(_db); err != nil {
			logrus.Errorf("Failed fetching credentials: %s", err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		var flow func(*http.Request) error
		if !u.HasCredentials() {
			flow = webAuthnBeginRegistration
		} else {
			flow = webAuthnLogin
		}

		if err := flow(req); err != nil {
			if wafc, ok := err.(errors.WebAuthFlowChallenge); ok {
				w.WriteHeader(200)
				w.Header().Add("content-type", "application/json")
				w.Header().Add("webauthn", wafc.Header())
				return
			}

			logrus.Errorf("Failed during webauthn flow: %s", err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		defer func() {
			if err := _sess.RenewToken(req.Context()); err != nil {
				logrus.Errorf("could not renew token")
			}
		}()
		handler(w, req, ps)
	})
}

func RequireAdmin(handler httprouter.Handle) httprouter.Handle {
	return RequireAuth(func(w http.ResponseWriter, req *http.Request, ps httprouter.Params) {
		user := req.Context().Value(constants.ContextUser).(*user.User)
		if !user.IsAdmin {
			requestAuth(w, http.StatusUnauthorized)
			return
		}
		handler(w, req, ps)
	})
}
