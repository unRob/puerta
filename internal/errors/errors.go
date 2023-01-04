// SPDX-License-Identifier: Apache-2.0
// Copyright © 2022 Roberto Hidalgo <nidito@un.rob.mx>
package errors

import (
	"encoding/base64"
	"encoding/json"

	"github.com/sirupsen/logrus"
)

type HTTPError interface {
	Error() string
	Code() int
}

func ToHTTP(err error) (string, int) {
	if err := err.(HTTPError); err != nil {
		return err.Error(), err.Code()
	}
	return err.Error(), 500
}

type AuthError interface {
	Error() string
	Code() int
	Log()
}

type InvalidCredentials struct {
	Status int
	Reason string
}

func (err InvalidCredentials) Error() string {
	return "Usuario o contraseña desconocidos"
}

func (err InvalidCredentials) Log() {
	logrus.Error(err.Reason)
}

func (err InvalidCredentials) Code() int {
	return err.Status
}

type WebAuthFlowChallenge struct {
	Flow string
	Data any
}

func (c WebAuthFlowChallenge) Error() string {
	b, err := json.Marshal(map[string]any{"webauthn": c.Flow, "data": c.Data})
	if err != nil {
		logrus.Errorf("Could not marshal data: %s", err)
		logrus.Errorf("data: %s", c.Data)
		return ""
	}

	return string(b)
}

func (c WebAuthFlowChallenge) Header() string {
	b, err := json.Marshal(c.Data)
	if err != nil {
		logrus.Errorf("Could not marshal data: %s", err)
		logrus.Errorf("data: %s", c.Data)
		return ""
	}

	return c.Flow + " " + base64.StdEncoding.EncodeToString([]byte(b))
}

func (c WebAuthFlowChallenge) Log() {
	logrus.Error("responding with webauthn challenge")
}

func (c WebAuthFlowChallenge) Code() int {
	return 418
}
