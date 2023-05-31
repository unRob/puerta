// SPDX-License-Identifier: Apache-2.0
// Copyright © 2022 Roberto Hidalgo <nidito@un.rob.mx>
package server

import (
	"bytes"
	"embed"
	"fmt"
	"io"
	"io/fs"
	"log"
	"mime"
	"net/http"
	"os"
	"time"

	"git.rob.mx/nidito/puerta/internal/auth"
	"git.rob.mx/nidito/puerta/internal/door"
	"git.rob.mx/nidito/puerta/internal/errors"
	"git.rob.mx/nidito/puerta/internal/push"
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
	Origin string `yaml:"origin"`
	// Protocol specifies the protocol for the webauthn origin
	Protocol string `yaml:"protocol"`
}

type Config struct {
	Name     string         `yaml:"name"`
	Adapter  map[string]any `yaml:"adapter"`
	HTTP     *HTTPConfig    `yaml:"http"`
	WebPush  *push.Config   `yaml:"push"`
	Timezone string         `yaml:"timezone"`
	DB       string         `yaml:"db"`
}

func ConfigDefaults(dbPath string) *Config {
	return &Config{
		DB: dbPath,
		HTTP: &HTTPConfig{
			Listen:   "localhost:8000",
			Origin:   "localhost",
			Protocol: "http",
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
	xforward := r.Header.Get("X-Forwarded-For")
	if xforward != "" {
		ip = xforward
	}
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
		output := w.Header()
		input := r.Header

		if input.Get("Access-Control-Request-Method") != "" {
			output.Set("Access-Control-Allow-Methods", input.Get("Allow"))
			output.Set("Access-Control-Allow-Origin", r.Host)
			output.Set("Access-Control-Allow-Credentials", "true")
			output.Set("Access-Control-Allow-Headers", "content-type,webauthn")
			output.Set("Access-Control-Expose-Headers", "webauthn")
			if r.Method == http.MethodOptions {
				// Set CORS headers
				// Adjust status code to 204
				w.WriteHeader(http.StatusOK)
				return
			}
		}

		if handler != nil {
			handler(w, r, params)
		}
	}
}

func notifyAdmins(message string) {
	subs := []*user.Subscription{}
	err := _db.SQL().
		SelectFrom("subscription as s").
		Join("user as u").
		On(`u.id = s.user and u.receives_notifications and u.is_admin`).
		All(&subs)
	if err != nil {
		logrus.Errorf("could not fetch subscriptions: %s", err)
	}

	logrus.Infof("notifying %v admins", len(subs))

	for _, sub := range subs {
		err := push.Notify(message, sub)
		if err != nil {
			logrus.Errorf("could not push notification to subscription %s: %s", sub.ID(), err)
		}
	}
}

func rex(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	var err error
	u := user.FromContext(r)

	defer func(req *http.Request, err error) {
		_, sqlErr := _db.Collection("log").Insert(newAuditLog(req, err))
		if sqlErr != nil {
			logrus.Errorf("could not record error log: %s", sqlErr)
		}
	}(r, err)

	err = u.IsAllowed(time.Now().In(TZ))
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
	go notifyAdmins(fmt.Sprintf("%s abrió la puerta", u.Name))

	fmt.Fprintf(w, `{"status": "ok"}`)
}

var _db db.Session
var TZ *time.Location = time.UTC

func Initialize(config *Config) (http.Handler, error) {
	devMode := os.Getenv("ENV") == "dev"
	router := httprouter.New()
	router.GlobalOPTIONS = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		allowCORS(nil)(w, r, nil)
	})

	if config.Timezone != "" {
		mtz, err := time.LoadLocation(config.Timezone)
		if err != nil {
			return nil, fmt.Errorf("Unknown timezone %s", config.Timezone)
		}
		TZ = mtz
	}

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

	origins := []string{config.HTTP.Protocol + "://" + config.HTTP.Origin}
	if devMode {
		origins = []string{config.HTTP.Protocol + "://" + config.HTTP.Listen}
	}

	wan, err := webauthn.New(&webauthn.Config{
		RPDisplayName: config.Name,
		RPID:          config.HTTP.Origin,
		RPOrigins:     origins,
	})
	if err != nil {
		return nil, err
	}

	push.Initialize(config.WebPush)

	var assetRoot http.FileSystem
	if devMode {
		pwd, _ := os.Getwd()
		dir := pwd + "/internal/server/static/"
		logrus.Warnf("serving static assets from %s", dir)
		assetRoot = http.Dir(dir)
	} else {
		subfs, err := fs.Sub(staticFiles, "static")
		if err != nil {
			log.Fatal(err)
		}
		assetRoot = http.FS(subfs)
	}

	mime.AddExtensionType(".webmanifest", "application/manifest+json")
	router.ServeFiles("/static/*filepath", assetRoot)
	router.GET("/login", renderTemplate(loginTemplate))
	router.GET("/", auth.RequireAuthOrRedirect(renderTemplate(indexTemplate), "/login"))
	router.GET("/admin-serviceworker.js", func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
		f, err := assetRoot.Open("/admin-serviceworker.js")
		if err != nil {
			sendError(w, err)
			return
		}

		buf, err := io.ReadAll(f)
		if err != nil {
			sendError(w, err)
			return
		}

		w.Header().Add("content-type", "application/javascript")
		w.WriteHeader(200)
		w.Write(buf)
	})
	router.GET("/admin", auth.RequireAdminOrRedirect(renderTemplate(bytes.ReplaceAll(adminTemplate, []byte("$PUSH_KEY$"), []byte(config.WebPush.Key.Public))), "/login?next=/admin"))

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
	router.POST("/api/push/subscribe", allowCORS(auth.RequireAdmin(auth.Enforce2FA(createSubscription))))
	router.POST("/api/push/unsubscribe", allowCORS(auth.RequireAdmin(auth.Enforce2FA(deleteSubscription))))

	return auth.Route(wan, _db, router), nil
}

func renderTemplate(template []byte) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
		w.Write(template)
	}
}
