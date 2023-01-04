// SPDX-License-Identifier: Apache-2.0
// Copyright © 2022 Roberto Hidalgo <nidito@un.rob.mx>
package server

import (
	"encoding/json"
	"net/http"

	"git.rob.mx/nidito/puerta/internal/user"
	"github.com/julienschmidt/httprouter"
	"github.com/sirupsen/logrus"
	"github.com/upper/db/v4"
	"golang.org/x/crypto/bcrypt"
)

func sendError(w http.ResponseWriter, err error) {
	logrus.Error(err)
	http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
}

func writeJSON(w http.ResponseWriter, data any) error {
	res, err := json.Marshal(data)
	if err != nil {
		return err
	}

	w.Header().Add("content-type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, err = w.Write(res)
	return err
}

func listUsers(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	users := []*user.User{}
	if err := _db.Collection("user").Find().All(&users); err != nil {
		sendError(w, err)
		return
	}

	writeJSON(w, users)
}

func userFromRequest(r *http.Request, u *user.User) (*user.User, error) {
	dec := json.NewDecoder(r.Body)
	res := &user.User{}
	if err := dec.Decode(&res); err != nil {
		return nil, err
	}
	logrus.Debugf("Unserialized user data: %v", res)

	if u == nil {
		u = &user.User{
			Handle: res.Handle,
		}
	}

	u.Name = res.Name
	u.Expires = res.Expires
	u.Greeting = res.Greeting
	u.IsAdmin = res.IsAdmin
	u.Require2FA = res.Require2FA
	u.Schedule = res.Schedule
	u.TTL = res.TTL

	if res.Password != "" {
		password, err := bcrypt.GenerateFromPassword([]byte(res.Password), bcrypt.DefaultCost)
		if err != nil {
			return nil, err
		}
		u.Password = string(password)
	}

	return u, nil

}

func createUser(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	user, err := userFromRequest(r, nil)
	if err != nil {
		sendError(w, err)
		return
	}

	if _, err := _db.Collection("user").Insert(user); err != nil {
		sendError(w, err)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

func getUser(w http.ResponseWriter, r *http.Request, params httprouter.Params) {
	this := user.User{}
	idString := params.ByName("id")

	if err := _db.Get(&this, db.Cond{"handle": idString}); err != nil {
		sendError(w, err)
		return
	}

	writeJSON(w, this)
}

func updateUser(w http.ResponseWriter, r *http.Request, params httprouter.Params) {
	logrus.Infof("updating user: %s", params.ByName("id"))
	user := user.User{}
	if err := _db.Get(&user, db.Cond{"handle": params.ByName("id")}); err != nil {
		logrus.Error(err)
		http.NotFound(w, r)
		return
	}

	modified, err := userFromRequest(r, &user)
	if err != nil {
		sendError(w, err)
		return
	}

	if err := _db.Collection("user").UpdateReturning(modified); err != nil {
		sendError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func deleteUser(w http.ResponseWriter, r *http.Request, params httprouter.Params) {
	err := _db.Collection("user").Find(db.Cond{"handle": params.ByName("id")}).Delete()
	if err != nil {
		sendError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func rexRecords(w http.ResponseWriter, r *http.Request, params httprouter.Params) {
	records := []*auditLog{}
	err := _db.Collection("log").Find().OrderBy("-timestamp").Limit(20).All(&records)
	if err != nil {
		sendError(w, err)
		return
	}

	writeJSON(w, records)
}
