// SPDX-License-Identifier: Apache-2.0
// Copyright © 2022 Roberto Hidalgo <nidito@un.rob.mx>
package server

import (
	"embed"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"time"

	"git.rob.mx/nidito/puerta/internal/auth"
	"git.rob.mx/nidito/puerta/internal/door"
	"git.rob.mx/nidito/puerta/internal/errors"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/julienschmidt/httprouter"
	"github.com/sirupsen/logrus"
	"github.com/upper/db/v4"
	"github.com/upper/db/v4/adapter/sqlite"
)

//go:embed login.html
var loginTemplate []byte

//go:embed index.html
var indexTemplate []byte

//go:embed admin.html
var adminTemplate []byte

//go:embed static/*
var staticFiles embed.FS

type HTTPConfig struct {
	Listen int    `yaml:"listen"`
	Domain string `yaml:"domain"`
}

type Config struct {
	Name    string         `yaml:"name"`
	Adapter map[string]any `yaml:"adapter"`
	HTTP    *HTTPConfig    `yaml:"http"`

	DB string `yaml:"db"`
}

func ConfigDefaults(dbPath string) *Config {
	return &Config{
		DB: dbPath,
		HTTP: &HTTPConfig{
			Listen: 8000,
			Domain: "localhost",
		},
	}
}

type auditLog struct {
	Timestamp    time.Time `db:"timestamp"`
	User         string    `db:"user"`
	SecondFactor bool      `db:"second_factor"`
	Failure      string    `db:"failure"`
	Err          string    `db:"error"`
	Success      bool      `db:"success"`
	IpAddress    string    `db:"ip_address"`
	UserAgent    string    `db:"user_agent"`
}

func newAuditLog(r *http.Request, err error) *auditLog {
	user := auth.UserFromContext(r)
	ip := r.RemoteAddr
	ua := r.Header.Get("user-agent")

	al := &auditLog{
		Timestamp:    time.Now(),
		User:         user.Handle,
		SecondFactor: user.Require2FA,
		IpAddress:    ip,
		UserAgent:    ua,
	}

	if err != nil {
		al.Failure = err.Error()
		if derr, ok := err.(door.Error); ok {
			al.Err = derr.Name()
			al.Failure = derr.Error()
		}
	}

	return al
}

func CORS(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Access-Control-Request-Method") != "" {
		// Set CORS headers
		header := w.Header()
		header.Set("Access-Control-Allow-Methods", r.Header.Get("Allow"))
		header.Set("Access-Control-Allow-Origin", "")
	}

	// Adjust status code to 204
	w.WriteHeader(http.StatusNoContent)
}

func rex(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	var err error
	user := r.Context().Value(auth.ContextUser).(*auth.User)

	defer func() {
		_, sqlErr := _db.Collection("log").Insert(newAuditLog(r, err))
		if sqlErr != nil {
			logrus.Errorf("could not record error log: %s", sqlErr)
		}
	}()

	err = user.IsAllowed(time.Now())
	if err != nil {
		logrus.Errorf("Denying rex to %s: %s", user.Name, err)
		http.Error(w, "Access denied", http.StatusForbidden)
		return
	}

	err = door.RequestToEnter(user.Name)

	if err != nil {
		message, code := errors.ToHTTP(err)
		http.Error(w, message, code)
		return
	}

	fmt.Fprintf(w, `{"status": "ok"}`)
}

var _db db.Session

func Initialize(config *Config) (http.Handler, error) {
	router := httprouter.New()
	router.GlobalOPTIONS = http.HandlerFunc(CORS)

	db := sqlite.ConnectionURL{
		Database: config.DB,
		Options: map[string]string{
			"_journal":      "WAL",
			"_busy_timeout": "5000",
		},
	}
	var err error
	_db, err = sqlite.Open(db)
	if err != nil {
		return nil, err
	}

	if err := door.Connect(config.Adapter); err != nil {
		return nil, err
	}

	uri := fmt.Sprintf("http://%s:%d", config.HTTP.Domain, config.HTTP.Listen)

	wan, err := webauthn.New(&webauthn.Config{
		RPDisplayName: config.Name,
		RPID:          config.HTTP.Domain,
		RPOrigins:     []string{uri},
		// RPIcon:        "https://go-webauthn.local/logo.png",
	})
	if err != nil {
		return nil, err
	}

	am := auth.NewManager(wan, _db)

	serverRoot, err := fs.Sub(staticFiles, "static")
	if err != nil {
		log.Fatal(err)
	}

	router.ServeFiles("/static/*filepath", http.FS(serverRoot))
	router.GET("/login", renderTemplate(loginTemplate))
	router.GET("/", am.RequireAuthOrRedirect(renderTemplate(indexTemplate), "/login"))
	router.POST("/api/login", am.NewSession)
	router.POST("/api/rex", am.Enforce2FA(rex))
	router.GET("/admin", am.RequireAdmin(renderTemplate(adminTemplate)))
	router.GET("/api/user", am.RequireAdmin(listUsers))
	// router.GET("/api/user/:id", am.RequireAdmin(getUser))
	router.GET("/api/user/:id", getUser)
	router.PUT("/api/user", am.RequireAdmin(am.Enforce2FA(createUser)))
	router.POST("/api/user/:id", am.RequireAdmin(am.Enforce2FA(updateUser)))
	router.DELETE("/api/user/:id", am.RequireAdmin(am.Enforce2FA(deleteUser)))

	return am.Route(router), nil
}

func renderTemplate(template []byte) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
		w.Write(template)
	}
}
