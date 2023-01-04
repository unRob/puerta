// SPDX-License-Identifier: Apache-2.0
// Copyright © 2022 Roberto Hidalgo <nidito@un.rob.mx>
package admin

import (
	"fmt"
	"os"

	"git.rob.mx/nidito/chinampa"
	"git.rob.mx/nidito/chinampa/pkg/command"
	"git.rob.mx/nidito/puerta/internal/server"
	"git.rob.mx/nidito/puerta/internal/user"
	"github.com/sirupsen/logrus"
	"github.com/upper/db/v4/adapter/sqlite"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
)

func init() {
	chinampa.Register(userAddCommand)
}

var userAddCommand = &command.Command{
	Path:        []string{"admin", "user", "create"},
	Summary:     "Create the initial user",
	Description: "",
	Arguments: command.Arguments{
		{
			Name:        "handle",
			Description: "the username to add",
			Required:    true,
		},
		{
			Name:        "name",
			Description: "the user's name",
			Required:    true,
		},
		{
			Name:        "password",
			Description: "the password to set for this user",
			Required:    true,
		},
	},
	Options: command.Options{
		"config": {
			Type:        "string",
			Default:     "./config.joao.yaml",
			Description: "the config to read from",
		},
		"db": {
			Type:        "string",
			Default:     "./puerta.db",
			Description: "the database to operate on",
		},
		"ttl": {
			Type:        "string",
			Description: "the ttl to set for the user",
			Default:     "30d",
		},
		"expires": {
			Type:        "string",
			Description: "the max cookie lifetime",
			Default:     "",
		},
		"schedule": {
			Type:        "string",
			Description: "the schedule to set for the user",
			Default:     "",
		},
		"greeting": {
			Type:        "string",
			Description: "a custom greeting for the user",
			Default:     "",
		},
		"admin": {
			Type:        "bool",
			Description: "make this user an admin",
		},
	},
	Action: func(cmd *command.Command) error {
		config := cmd.Options["config"].ToValue().(string)
		db := cmd.Options["db"].ToValue().(string)

		expires := cmd.Options["expires"].ToString()
		schedule := cmd.Options["schedule"].ToString()
		ttl := cmd.Options["ttl"].ToString()
		greeting := cmd.Options["greeting"].ToString()
		admin := cmd.Options["admin"].ToValue().(bool)

		data, err := os.ReadFile(config)
		if err != nil {
			return fmt.Errorf("could not read config file: %w", err)
		}

		cfg := server.ConfigDefaults(db)

		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return fmt.Errorf("could not unserialize yaml at %s: %w", config, err)
		}

		sess, err := sqlite.Open(sqlite.ConnectionURL{
			Database: cfg.DB,
			// Options:  {},
		})
		if err != nil {
			return fmt.Errorf("could not open connection to db: %s", err)
		}

		password, err := bcrypt.GenerateFromPassword([]byte(cmd.Arguments[2].ToString()), bcrypt.DefaultCost)
		if err != nil {
			return fmt.Errorf("could not hash password: %s", err)
		}

		u := &user.User{
			Name:     cmd.Arguments[1].ToString(),
			Password: string(password),
			Handle:   cmd.Arguments[0].ToString(),
			Greeting: greeting,
			IsAdmin:  admin,
		}

		if ttl != "" {
			u.TTL = &user.TTL{}
			if err := u.TTL.Scan(ttl); err != nil {
				return fmt.Errorf("could not decode ttl %s: %s", ttl, err)
			}
		}

		if schedule != "" {
			u.Schedule = &user.Schedule{}
			if err := u.Schedule.Scan(schedule); err != nil {
				return fmt.Errorf("could not decode schedule %s: %s", schedule, err)
			}
		}

		if expires != "" {
			t := &user.UTCTime{}
			if err := t.Scan(expires); err != nil {
				return fmt.Errorf("could not decode expires %s: %s", expires, err)
			}
			u.Expires = t
		}

		res, err := sess.Collection("user").Insert(u)
		if err != nil {
			return fmt.Errorf("failed to insert %s", err)
		}

		logrus.Infof("Created user %s with ID: %d", u.Name, res.ID())
		return nil

	},
}
