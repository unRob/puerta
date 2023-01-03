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

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/sirupsen/logrus"
	"github.com/upper/db/v4"
)

const SessionNameWANAuth = "wan-auth"
const SessionNameWANRegister = "wan-register"
const HeaderNameWAN = "webauthn"

func (am *Manager) WebAuthnBeginRegistration(req *http.Request) error {
	user := UserFromContext(req)
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

	am.sess.Put(req.Context(), SessionNameWANRegister, b.Bytes())
	return WebAuthFlowChallenge{"register", &options}
}

func (am *Manager) WebAuthnFinishRegistration(req *http.Request) error {
	user := UserFromContext(req)
	sd := am.sess.PopBytes(req.Context(), SessionNameWANRegister)
	if sd == nil {
		return fmt.Errorf("error finishing webauthn registration: no session found for user")
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

func (am *Manager) WebAuthnLogin(req *http.Request) error {
	user := UserFromContext(req)
	sd := am.sess.PopBytes(req.Context(), SessionNameWANAuth)
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

		am.sess.Put(req.Context(), SessionNameWANAuth, b.Bytes())

		return WebAuthFlowChallenge{"login", &options}
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

	_, err = am.wan.ValidateLogin(user, sessionData, response)
	return err
}

func (am *Manager) Cleanup() error {
	return am.db.Collection("session").Find(db.Cond{"Expires": db.Before(time.Now())}).Delete()
}
