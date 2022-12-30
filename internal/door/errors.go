// SPDX-License-Identifier: Apache-2.0
// Copyright © 2022 Roberto Hidalgo <nidito@un.rob.mx>
package door

import (
	"fmt"
	"net/http"
)

type DoorCommunicationError struct {
	during string
	err    error
}

func (err *DoorCommunicationError) Error() string {
	return fmt.Sprintf("ould not get door status while %s: %s", err.during, err.err.Error())
}

func (err *DoorCommunicationError) Code() int {
	return http.StatusInternalServerError
}

type DoorAlreadyOpen struct{}

func (err *DoorAlreadyOpen) Error() string {
	return "door is already open"
}

func (err *DoorAlreadyOpen) Code() int {
	return http.StatusPreconditionFailed
}
