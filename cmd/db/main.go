package db

import (
	"embed"
	"fmt"
	"os"
	"strings"
	"time"

	"git.rob.mx/nidito/chinampa/pkg/command"
	"git.rob.mx/nidito/puerta/internal/server"
	"github.com/sirupsen/logrus"
	"github.com/upper/db/v4"
	"github.com/upper/db/v4/adapter/sqlite"
	"gopkg.in/yaml.v3"
)

//go:embed migrations/*
var migrationsDir embed.FS

const baseMigration = "0000-00-00-base.sql"

func runMigration(sess db.Session, path string) error {
	contents, err := migrationsDir.ReadFile("migrations/" + path)
	if err != nil {
		return err
	}
	q := fmt.Sprintf("%s", contents)
	logrus.Infof("running migration\n %s", q)
	return sess.Tx(func(sess db.Session) error {
		q += `

		;

		INSERT INTO migrations (name, applied) VALUES (?, ?);
		`
		_, err = sess.SQL().Exec(q, path, time.Now().UTC().Format(time.RFC3339))

		return err
	})
}

var MigrationsCommand = &command.Command{
	Path:        []string{"db", "migrate"},
	Summary:     "Runs database migrations",
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
		dbPath := cmd.Options["db"].ToValue().(string)

		data, err := os.ReadFile(config)
		if err != nil {
			return fmt.Errorf("could not read config file: %w", err)
		}

		cfg := server.ConfigDefaults(dbPath)

		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return fmt.Errorf("could not unserialize yaml at %s: %w", config, err)
		}

		logger := logrus.New()
		logger.SetFormatter(&logrus.JSONFormatter{DisableTimestamp: false})

		sess, err := sqlite.Open(sqlite.ConnectionURL{
			Database: cfg.DB,
			Options: map[string]string{
				"_journal":      "WAL",
				"_busy_timeout": "5000",
			},
		})
		if err != nil {
			return err
		}

		defer sess.Close()
		cols, err := sess.Collections()
		if err != nil {
			return err
		}

		needsInitialMigration := true
		for _, col := range cols {
			if col.Name() == "migrations" {
				logger.Infof("found migrations table: %s", col.Name())
				needsInitialMigration = false
				break
			}
		}

		if needsInitialMigration {
			logger.Info("Running initial migration")
			if err := runMigration(sess, baseMigration); err != nil {
				logger.Fatalf("Could not run base migration: %s", err)
			}
		}

		migrations, err := migrationsDir.ReadDir("migrations")
		if err != nil {
			return err
		}

		for _, mig := range migrations {
			name := mig.Name()
			if strings.HasSuffix(name, ".sql") && mig.Type().IsRegular() && name != baseMigration {

				cnt, err := sess.Collection("migrations").Find(db.Cond{"name": name}).Count()
				if err != nil {
					return fmt.Errorf("Could not count migrations for %s: %s", name, err)
				}

				if cnt > 0 {
					logger.Infof("Already applied %s", name)
					continue
				}

				logger.Infof("Running migration: %s", name)
				if err := runMigration(sess, name); err != nil {
					logger.Fatalf("Could not run base migration: %s", err)
				}
			}
		}

		return nil
	},
}
