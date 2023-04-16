// SPDX-License-Identifier: Apache-2.0
// Copyright © 2022 Roberto Hidalgo <nidito@un.rob.mx>
package main

import (
	"os"

	"git.rob.mx/nidito/chinampa"
	"git.rob.mx/nidito/chinampa/pkg/runtime"
	"git.rob.mx/nidito/puerta/cmd/admin"
	"git.rob.mx/nidito/puerta/cmd/db"
	"git.rob.mx/nidito/puerta/cmd/hue"
	"git.rob.mx/nidito/puerta/cmd/server"
	"github.com/sirupsen/logrus"
)

func main() {
	logrus.SetFormatter(&logrus.TextFormatter{
		DisableLevelTruncation: true,
		DisableTimestamp:       true,
		ForceColors:            runtime.ColorEnabled(),
	})

	if runtime.DebugEnabled() {
		logrus.SetLevel(logrus.DebugLevel)
		logrus.Debug("Debugging enabled")
	}

	cfg := chinampa.Config{
		Name:        "puerta",
		Version:     "0.0.0",
		Summary:     "opens the door to my house",
		Description: "Does other door related stuff too.",
	}

	chinampa.Register(
		admin.UserAddCommand,
		admin.UserReset2faCommand,
		hue.SetupHueCommand,
		hue.TestHueCommand,
		server.ServerCommand,
		db.MigrationsCommand,
	)

	if err := chinampa.Execute(cfg); err != nil {
		logrus.Errorf("total failure: %s", err)
		os.Exit(2)
	}
}
