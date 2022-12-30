// SPDX-License-Identifier: Apache-2.0
// Copyright © 2022 Roberto Hidalgo <nidito@un.rob.mx>
package server

import (
	"fmt"
	"net/http"
	"os"

	"git.rob.mx/nidito/chinampa"
	"git.rob.mx/nidito/chinampa/pkg/command"
	"git.rob.mx/nidito/puerta/internal/server"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

func init() {
	chinampa.Register(serverCommand)
}

var serverCommand = &command.Command{
	Path:        []string{"server"},
	Summary:     "Runs the http server",
	Description: "",
	Options: command.Options{
		"config": {
			Type:    "string",
			Default: "./config.joao.yaml",
		},
		"db": {
			Type:    "string",
			Default: "./puerta.db",
		},
	},
	Action: func(cmd *command.Command) error {
		config := cmd.Options["config"].ToValue().(string)
		db := cmd.Options["db"].ToValue().(string)

		data, err := os.ReadFile(config)
		if err != nil {
			return fmt.Errorf("could not read config file: %w", err)
		}

		cfg := server.ConfigDefaults(db)

		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return fmt.Errorf("could not unserialize yaml at %s: %w", config, err)
		}

		logger := logrus.New()
		logger.SetFormatter(&logrus.JSONFormatter{DisableTimestamp: false})

		router, err := server.Initialize(cfg)
		if err != nil {
			return err
		}

		logrus.Infof("Listening on port %d", cfg.HTTP.Listen)
		return http.ListenAndServe(fmt.Sprintf(":%d", cfg.HTTP.Listen), router)
	},
}
