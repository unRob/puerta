// SPDX-License-Identifier: Apache-2.0
// Copyright © 2022 Roberto Hidalgo <nidito@un.rob.mx>
package auth

import (
	"encoding/json"

	"github.com/sirupsen/logrus"
)

type AuthError interface {
	Error() string
	Code() int
	Log()
}

type InvalidCredentials struct {
	code   int
	reason string
}

func (err InvalidCredentials) Error() string {
	return "Usuario o contraseña desconocidos"
}

func (err InvalidCredentials) Log() {
	logrus.Error(err.reason)
}

func (err InvalidCredentials) Code() int {
	return err.code
}

type WebAuthFlowChallenge struct {
	flow string
	data any
}

func (c WebAuthFlowChallenge) Error() string {
	b, err := json.Marshal(map[string]any{"webauthn": c.flow, "data": c.data})
	if err != nil {
		logrus.Errorf("Could not marshal data: %s", err)
		logrus.Errorf("data: %s", c.data)
		return ""
	}

	return string(b)
}

func (c WebAuthFlowChallenge) Log() {
	logrus.Error("responding with webauthn challenge")
}

func (c WebAuthFlowChallenge) Code() int {
	return 418
}
