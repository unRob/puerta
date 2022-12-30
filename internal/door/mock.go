// SPDX-License-Identifier: Apache-2.0
// Copyright © 2022 Roberto Hidalgo <nidito@un.rob.mx>
package door

import (
	"time"

	"github.com/sirupsen/logrus"
)

func init() {
	_register("dry-run", NewMock)
}

type mockDoor struct {
	Status        bool
	FailedToOpen  error
	FailedToClose error
}

func NewMock(config map[string]any) Door {
	logrus.Info("Initializing mock client")
	return &mockDoor{
		Status: false,
	}
}

func (md *mockDoor) IsOpen() (bool, error) {
	return md.Status, nil
}

func (md *mockDoor) Open(errors chan<- error, done chan<- bool) {
	defer close(errors)
	if md.FailedToOpen != nil {
		errors <- md.FailedToOpen
		return
	}

	md.Status = true
	errors <- nil

	time.Sleep(4 * time.Second)
	md.Status = false

	if md.FailedToClose != nil {
		errors <- md.FailedToClose
		return
	}

	done <- true
}
