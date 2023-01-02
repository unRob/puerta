// SPDX-License-Identifier: Apache-2.0
// Copyright © 2022 Roberto Hidalgo <nidito@un.rob.mx>
package door

import (
	"fmt"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"
)

var (
	isOpening bool
	statusMu  sync.Mutex
	Active    Door
)

type newDoorFunc func(map[string]any) (Door, error)

var adapters = &struct {
	factories map[string]newDoorFunc
	names     []string
}{
	factories: map[string]newDoorFunc{},
	names:     []string{},
}

func _register(name string, factory newDoorFunc) {
	adapters.factories[name] = factory
	adapters.names = append(adapters.names, name)
}

type Door interface {
	IsOpen() (bool, error)
	Open(errors chan<- error, done chan<- bool)
}

func setStatus(status bool) {
	statusMu.Lock()
	isOpening = status
	statusMu.Unlock()
}

// RequestToEnter opens the door unless it's already open or opening
func RequestToEnter(username string) error {
	statusMu.Lock()
	if isOpening {
		defer statusMu.Unlock()
		return &ErrorCommunication{"checking status", fmt.Errorf("Door is busy processing another request")}
	}

	isOpen, err := Active.IsOpen()
	if err != nil {
		statusMu.Unlock()
		return &ErrorCommunication{"checking status", err}
	} else if isOpen {
		statusMu.Unlock()
		return &ErrorAlreadyOpen{}
	}

	// okay, we're triggering an open and preventing others
	// from doing the same until this function toggles this value again
	isOpening = true
	statusMu.Unlock()
	logrus.Infof("Opening door for %s\n", username)

	errors := make(chan error, 2)
	done := make(chan bool)
	go Active.Open(errors, done)

	if err = <-errors; err != nil {
		setStatus(false)
		return &ErrorCommunication{"opening", err}
	}

	logrus.Infof("Door opened for %s", username)

	go func() {
		// Door might continue working on stuff after we Open,
		// wait for done or another error
		select {
		case <-done:
			logrus.Info("REX complete")
		case err, ok := <-errors:
			if ok && err != nil {
				logrus.Errorf("Failed during power off: %s", err)
			} else if ok {
				logrus.Info("Door power shut off correctly")
			}
		}
		// now it's safe for others to open the door
		setStatus(false)
	}()
	return nil
}

func Connect(config map[string]any) (err error) {
	adapterName, hasAdapter := config["kind"]
	if !hasAdapter {
		return fmt.Errorf("missing DOOR_ADAPTER")
	}

	factory, exists := adapters.factories[adapterName.(string)]
	if !exists {
		return fmt.Errorf("unknown DOOR_ADAPTER \"%s\", not one of [%s]", adapterName, strings.Join(adapters.names, ","))
	}

	Active, err = factory(config)
	return err
}
