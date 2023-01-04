// SPDX-License-Identifier: Apache-2.0
// Copyright © 2022 Roberto Hidalgo <nidito@un.rob.mx>
package auth

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"git.rob.mx/nidito/puerta/internal/errors"
	"git.rob.mx/nidito/puerta/internal/user"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/sirupsen/logrus"
	"github.com/upper/db/v4"
)

const SessionNameWANAuth = "wan-auth"
const SessionNameWANRegister = "wan-register"
const HeaderNameWAN = "webauthn"

func webAuthnBeginRegistration(req *http.Request) error {
	user := user.FromContext(req)
	logrus.Infof("Starting webauthn registration for %s", user.Name)
	options, sessionData, err := _wan.BeginRegistration(user)
	if err != nil {
		err = fmt.Errorf("error starting webauthn: %s", err)
		logrus.Error(err)
		return err
	}

	var b bytes.Buffer
	if err := json.NewEncoder(&b).Encode(&sessionData); err != nil {
		return err
	}

	_sess.Put(req.Context(), SessionNameWANRegister, b.Bytes())
	return errors.WebAuthFlowChallenge{Flow: "register", Data: &options}
}

func webAuthnFinishRegistration(req *http.Request) error {
	u := user.FromContext(req)
	sd := _sess.PopBytes(req.Context(), SessionNameWANRegister)
	if sd == nil {
		return fmt.Errorf("error finishing webauthn registration: no session found for user")
	}

	var sessionData webauthn.SessionData
	err := json.Unmarshal(sd, &sessionData)
	if err != nil {
		return err
	}

	cred, err := _wan.FinishRegistration(u, sessionData, req)
	if err != nil {
		return fmt.Errorf("error finishing webauthn registration: %s", err)
	}

	data, err := json.Marshal(cred)
	if err != nil {
		return fmt.Errorf("error encoding webauthn credential for storage: %s", err)
	}
	credential := &user.Credential{
		UserID: u.ID,
		Data:   string(data),
	}

	_, err = _db.Collection("credential").Insert(credential)
	return err
}

func webAuthnLogin(req *http.Request) error {
	user := user.FromContext(req)
	sd := _sess.PopBytes(req.Context(), SessionNameWANAuth)
	if sd == nil {
		logrus.Infof("Starting webauthn login flow for %s", user.Name)

		options, sessionData, err := _wan.BeginLogin(user)
		if err != nil {
			return fmt.Errorf("error starting webauthn login: %s", err)
		}

		var b bytes.Buffer
		if err := json.NewEncoder(&b).Encode(&sessionData); err != nil {
			return fmt.Errorf("could not encode json: %s", err)
		}

		_sess.Put(req.Context(), SessionNameWANAuth, b.Bytes())

		return errors.WebAuthFlowChallenge{Flow: "login", Data: &options}
	}

	var sessionData webauthn.SessionData
	err := json.Unmarshal(sd, &sessionData)
	if err != nil {
		return err
	}

	challengeResponse := req.Header.Get(HeaderNameWAN)
	if challengeResponse == "" {
		return fmt.Errorf("missing webauthn header")
	}

	challengeBytes, err := base64.StdEncoding.DecodeString(challengeResponse)
	if err != nil {
		return fmt.Errorf("unparseable webauthn header value")
	}

	response, err := protocol.ParseCredentialRequestResponseBody(bytes.NewBuffer(challengeBytes))
	if err != nil {
		return fmt.Errorf("could not parse webauthn request into protocol: %w", err)
	}

	_, err = _wan.ValidateLogin(user, sessionData, response)
	return err
}

func Cleanup() error {
	return _db.Collection("session").Find(db.Cond{"Expires": db.Before(time.Now())}).Delete()
}
