// SPDX-License-Identifier: Apache-2.0
// Copyright © 2022 Roberto Hidalgo <nidito@un.rob.mx>
package hue

import (
	"fmt"
	"os"

	"git.rob.mx/nidito/chinampa/pkg/command"
	"git.rob.mx/nidito/puerta/internal/door"
	"github.com/sirupsen/logrus"
)

var SetupHueCommand = &command.Command{
	Path:        []string{"hue", "setup"},
	Summary:     "Creates a local hue user and finds out available plugs",
	Description: "",
	Arguments: command.Arguments{
		{
			Name:        "ip",
			Description: "The ip address of the bridge",
			Required:    true,
		},
		{
			Name:        "domain",
			Description: "the domain or application name to use when registering",
			Default:     "puerta.nidi.to",
		},
	},
	Action: func(cmd *command.Command) error {
		ip := cmd.Arguments[0].ToValue().(string)
		domain := cmd.Arguments[1].ToValue().(string)

		logrus.Infof("Setting up with bridge at %s, app %s", ip, domain)
		doorI, err := door.NewHue(map[string]any{
			"ip":       ip,
			"username": "",
			"device":   -1,
		})
		if err != nil {
			return fmt.Errorf("could not connect to door: %s", err)
		}

		adapter := doorI.(*door.Hue)

		return adapter.Setup(os.Args[2])
	},
}

var TestHueCommand = &command.Command{
	Path:        []string{"hue", "test"},
	Summary:     "Uses a given configuration to open door",
	Description: "",
	Arguments: command.Arguments{
		{
			Name:        "ip",
			Description: "The ip address of the bridge",
			Required:    true,
		},
		{
			Name:        "username",
			Description: "An existing bridge username",
			Required:    true,
		},
		{
			Name:        "device",
			Description: "The device ID to test",
			Required:    true,
		},
	},
	Action: func(cmd *command.Command) error {
		ip := cmd.Arguments[0].ToValue().(string)
		username := cmd.Arguments[1].ToValue().(string)
		device := cmd.Arguments[2].ToValue().(string)

		logrus.Infof("Testing bridge at %s, username %s, device %s", ip, username, device)

		err := door.Connect(map[string]any{
			"adapter":  "hue",
			"ip":       ip,
			"username": username,
			"device":   device,
		})
		if err != nil {
			return fmt.Errorf("could not connect to door: %s", err)
		}
		return door.RequestToEnter("test")
	},
}
