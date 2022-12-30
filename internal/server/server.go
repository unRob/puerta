// SPDX-License-Identifier: Apache-2.0
// Copyright © 2022 Roberto Hidalgo <nidito@un.rob.mx>
package server

import (
	"embed"
	"fmt"
	"io/fs"
	"log"
	"net/http"

	"git.rob.mx/nidito/puerta/internal/auth"
	"git.rob.mx/nidito/puerta/internal/door"
	"git.rob.mx/nidito/puerta/internal/errors"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/julienschmidt/httprouter"
	"github.com/upper/db/v4"
	"github.com/upper/db/v4/adapter/sqlite"
)

//go:embed login.html
var loginTemplate []byte

//go:embed index.html
var indexTemplate []byte

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
	userName := r.Context().Value(auth.ContextUserName).(string)

	if err := door.RequestToEnter(_door, userName); err != nil {
		message, code := errors.ToHTTP(err)
		http.Error(w, message, code)
		return
	}

	fmt.Fprintf(w, `{"status": "ok"}`)
}

var _db db.Session
var _door door.Door

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

	_door, err = door.NewDoor(config.Adapter)
	if err != nil {
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

	am := auth.NewManager(wan, _door, _db)

	serverRoot, err := fs.Sub(staticFiles, "static")
	if err != nil {
		log.Fatal(err)
	}

	router.ServeFiles("/static/*filepath", http.FS(serverRoot))
	router.GET("/login", renderTemplate(loginTemplate))
	router.GET("/", am.Protected(renderTemplate(indexTemplate), true, false))
	router.POST("/api/login", am.NewSession)
	router.POST("/api/rex", am.Protected(rex, false, true))

	return am.Route(router), nil
}

func renderTemplate(template []byte) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
		w.Write(template)
	}
}
