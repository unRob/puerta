// SPDX-License-Identifier: Apache-2.0
// Copyright © 2022 Roberto Hidalgo <nidito@un.rob.mx>
package door

import (
	"context"
	"time"

	"github.com/amimof/huego"
	hue "github.com/amimof/huego"

	"github.com/sirupsen/logrus"
)

type HueConfig struct {
	ip       string
	username string
	device   int
}

type Hue struct {
	bridge *hue.Bridge
	device *hue.Light
	config *HueConfig
}

func init() {
	_register("hue", NewHue)
}

func NewHue(config map[string]any) Door {

	cfg := &HueConfig{
		ip:       config["ip"].(string),
		username: config["username"].(string),
		device:   -1,
	}
	if config["device"] != nil {
		cfg.device = config["device"].(int)
	}

	h := &Hue{
		bridge: huego.New(cfg.ip, cfg.username),
		config: cfg,
	}

	logrus.Infof("Hue client for %s starting", cfg.ip)

	if cfg.username != "" && cfg.device > -1 {
		device, err := h.bridge.GetLight(cfg.device)
		if err != nil {
			panic(err)
		}
		h.device = device
	}
	return h
}

func (h *Hue) Setup(domain string) error {
	if h.config.username == "" {
		logrus.Info("Pairing with bridge, please press the button")
		user, err := h.bridge.CreateUser(domain)
		if err != nil {
			return err
		}

		logrus.Infof("Created user id: %s", user)
		h.bridge = h.bridge.Login(user)
	}

	if h.config.device == -1 {
		logrus.Info("Looking for devices...")

		lights, err := h.bridge.GetLights()
		if err != nil {
			return err
		}

		for _, l := range lights {
			if l.Type == "On/Off plug-in unit" {
				logrus.Infof("Found %s named %s with ID: %d", l.ProductName, l.Name, l.ID)
			} else {
				logrus.Debugf("Found %s (%s) named %s with ID: %d", l.Type, l.ProductName, l.Name, l.ID)
			}
		}
	}

	logrus.Info("Setup complete")
	return nil
}

func (h *Hue) IsOpen() (bool, error) {
	return h.device.IsOn(), nil
}

func (h *Hue) Open(errors chan<- error, done chan<- bool) {
	defer close(errors)
	defer close(done)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := h.device.SetStateContext(ctx, hue.State{On: true})

	if err != nil {
		errors <- err
		return
	}

	errors <- nil

	time.Sleep(4 * time.Second)

	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = h.device.SetStateContext(ctx, hue.State{On: false})

	if err != nil {
		errors <- err
		return
	}

	done <- true
}

func (h *Hue) Close(errors chan error) {
	err, ok := <-errors
	if ok && err != nil {
		logrus.Errorf("Failed during power off: %s", err)
		return
	} else if ok {
		logrus.Info("Door power shut off correctly")
	}
}
