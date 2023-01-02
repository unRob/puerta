// SPDX-License-Identifier: Apache-2.0
// Copyright © 2022 Roberto Hidalgo <nidito@un.rob.mx>
package door

import (
	"fmt"
	"net/http"
)

type ErrorCommunication struct {
	during string
	err    error
}

func (err *ErrorCommunication) Error() string {
	return fmt.Sprintf("could not get door status while %s: %s", err.during, err.err.Error())
}

func (err *ErrorCommunication) Code() int {
	return http.StatusInternalServerError
}

func (err *ErrorCommunication) Name() string {
	return "communication-error"
}

type ErrorAlreadyOpen struct{}

func (err *ErrorAlreadyOpen) Error() string {
	return "door is already open"
}

func (err *ErrorAlreadyOpen) Code() int {
	return http.StatusPreconditionFailed
}

func (err *ErrorAlreadyOpen) Name() string {
	return "already-open"
}

type Error interface {
	Error() string
	Code() int
	Name() string
}
