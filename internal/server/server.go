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
	"git.rob.mx/nidito/puerta/internal/user"
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
	// Listen is a hostname:port
	Listen string `yaml:"listen"`
	// Origin describes the http origins to allow
	Origin string `yaml:"domain"`
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
			Listen: "localhost:8000",
			Origin: "http://localhost:8000",
		},
	}
}

type auditLog struct {
	Timestamp    string `db:"timestamp" json:"timestamp"`
	User         string `db:"user" json:"user"`
	SecondFactor bool   `db:"second_factor" json:"second_factor"`
	Failure      string `db:"failure" json:"failure"`
	Err          string `db:"error" json:"error"`
	IpAddress    string `db:"ip_address" json:"ip_address"`
	UserAgent    string `db:"user_agent" json:"user_agent"`
}

func newAuditLog(r *http.Request, err error) *auditLog {
	u := user.FromContext(r)
	ip := r.RemoteAddr
	ua := r.Header.Get("user-agent")

	al := &auditLog{
		Timestamp:    time.Now().UTC().Format(time.RFC3339),
		User:         u.Handle,
		SecondFactor: u.Require2FA,
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

func allowCORS(handler httprouter.Handle) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, params httprouter.Params) {
		header := w.Header()
		header.Set("Access-Control-Allow-Methods", "GET,PUT,POST,DELETE")
		header.Set("Access-Control-Allow-Origin", "http://localhost:8080")
		header.Set("Access-Control-Allow-Credentials", "true")
		header.Set("Access-Control-Allow-Headers", "content-type,webauthn")
		header.Set("Access-Control-Expose-Headers", "webauthn")

		if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
			// Set CORS headers
			// Adjust status code to 204
			w.WriteHeader(http.StatusOK)
			return
		}

		if handler != nil {
			handler(w, r, params)
		}
	}
}

func CORS(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Access-Control-Request-Method") != "" {
		// Set CORS headers
		header := w.Header()
		header.Set("Access-Control-Allow-Methods", r.Header.Get("Allow"))
		header.Set("Access-Control-Allow-Origin", "http://localhost:8080")
		header.Set("Access-Control-Allow-Credentials", "true")
		header.Set("Access-Control-Allow-Headers", "content-type,webauthn")
		header.Set("Access-Control-Expose-Headers", "webauthn")
	}

	// Adjust status code to 204
	w.WriteHeader(http.StatusNoContent)
}

func rex(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	var err error
	u := user.FromContext(r)

	defer func() {
		_, sqlErr := _db.Collection("log").Insert(newAuditLog(r, err))
		if sqlErr != nil {
			logrus.Errorf("could not record error log: %s", sqlErr)
		}
	}()

	err = u.IsAllowed(time.Now())
	if err != nil {
		logrus.Errorf("Denying rex to %s: %s", u.Name, err)
		http.Error(w, "Access denied", http.StatusForbidden)
		return
	}

	err = door.RequestToEnter(u.Name)

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

	wan, err := webauthn.New(&webauthn.Config{
		RPDisplayName: config.Name,
		RPID:          config.HTTP.Origin,
		RPOrigins:     []string{config.HTTP.Listen},
		// RPIcon:        "https://go-webauthn.local/logo.png",
	})
	if err != nil {
		return nil, err
	}

	auth.Initialize(wan, _db)

	serverRoot, err := fs.Sub(staticFiles, "static")
	if err != nil {
		log.Fatal(err)
	}

	router.ServeFiles("/static/*filepath", http.FS(serverRoot))
	router.GET("/login", renderTemplate(loginTemplate))
	router.GET("/", auth.RequireAuthOrRedirect(renderTemplate(indexTemplate), "/login"))
	router.GET("/admin", auth.RequireAdmin(renderTemplate(adminTemplate)))

	// regular api
	router.POST("/api/login", auth.LoginHandler)
	router.POST("/api/webauthn/register", auth.RequireAuth(auth.RegisterSecondFactor()))
	router.POST("/api/rex", allowCORS(auth.Enforce2FA(rex)))

	// admin api
	router.GET("/api/log", allowCORS(auth.RequireAdmin(rexRecords)))
	router.GET("/api/user", allowCORS(auth.RequireAdmin(listUsers)))
	router.GET("/api/user/:id", allowCORS(auth.RequireAdmin(getUser)))
	router.POST("/api/user", allowCORS(auth.RequireAdmin(auth.Enforce2FA(createUser))))
	router.POST("/api/user/:id", allowCORS(auth.RequireAdmin(auth.Enforce2FA(updateUser))))
	router.DELETE("/api/user/:id", allowCORS(auth.RequireAdmin(auth.Enforce2FA(deleteUser))))

	return auth.Route(router), nil
}

func renderTemplate(template []byte) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
		w.Write(template)
	}
}
