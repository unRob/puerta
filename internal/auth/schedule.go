// SPDX-License-Identifier: Apache-2.0
// Copyright © 2022 Roberto Hidalgo <nidito@un.rob.mx>
package auth

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

func parseHour(src string) (float64, error) {
	hm := strings.Split(src, ":")
	if len(hm) == 1 {
		return strconv.ParseFloat(hm[0], 32)
	}

	if len(hm) == 2 {
		h, err := strconv.ParseFloat(hm[0], 32)
		if err != nil {
			return 0.0, err
		}
		m, err := strconv.ParseFloat(hm[1], 32)
		if err != nil {
			return 0.0, err
		}
		return h + (m / 60.0), nil
	}

	return 0.0, fmt.Errorf("unknown format for hour: %s", hm)

}

type UserSchedule struct {
	src   string
	days  []int
	hours []float64
}

func (d UserSchedule) MarshalDB() ([]byte, error) {
	return json.Marshal(d.src)
}

func (d *UserSchedule) UnmarshalDB(b []byte) error {
	var v string
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}

	*d = UserSchedule{src: v}
	for _, kv := range strings.Split(v, " ") {
		kvSlice := strings.Split(kv, "=")
		key := kvSlice[0]
		values := strings.Split(kvSlice[1], "-")
		switch key {
		case "days":
			from, err := strconv.Atoi(values[0])
			if err != nil {
				return err
			}
			until, err := strconv.Atoi(values[1])
			if err != nil {
				return err
			}
			logrus.Infof("Parsed schedule days from: %d until %d", from, until)
			d.days = []int{from, until}
		case "hours":
			from, err := parseHour(values[0])
			if err != nil {
				return err
			}
			until, err := parseHour(values[1])
			if err != nil {
				return err
			}
			logrus.Infof("Parsed schedule hours from: %f until %f", from, until)
			d.hours = []float64{from, until}
		}
	}

	return nil
}

func (sch *UserSchedule) AllowedAt(t time.Time) bool {
	weekDay := int(t.Weekday())
	h, m, s := t.Clock()
	fractionalHour := float64(h) + (float64(m*60.0+s) / 3600.0)

	logrus.Infof("Validating access at weekday %d, hour %f from rules: days=%v hours=%v at %s", weekDay, fractionalHour, sch.days, sch.hours, t.String())
	if sch.days != nil {
		if weekDay < sch.days[0] || weekDay > sch.days[1] {
			return false
		}
	}

	if sch.hours != nil {
		if fractionalHour < sch.hours[0] || fractionalHour > sch.hours[1] {
			return false
		}
	}

	return true
}
