// SPDX-License-Identifier: Apache-2.0
// Copyright © 2022 Roberto Hidalgo <nidito@un.rob.mx>
package user

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/upper/db/v4"
)

var DefaultTTL = TTL{src: "30d", duration: time.Hour * 24 * 30}

type TTL struct {
	src      string
	duration time.Duration
}

func (ttl *TTL) Parse() (err error) {
	if ttl.src == "" {
		return fmt.Errorf("could not parse empty ttl")
	}
	suffix := ttl.src[len(ttl.src)-1]

	toParse := ttl.src
	if suffix == 'd' || suffix == 'w' || suffix == 'M' {
		multiplier := 1
		switch suffix {
		case 'd':
			multiplier = 24
		case 'w':
			multiplier = 24 * 7
		case 'M':
			multiplier = 24 * 7 * 30
		default:
			err = fmt.Errorf("unknown suffix for time duration %s", string(suffix))
			return
		}

		toParse = toParse[0 : len(toParse)-1]
		var days int
		days, err = strconv.Atoi(toParse)
		if err != nil {
			return
		}

		toParse = fmt.Sprintf("%dh", days*multiplier)
	}
	ttl.duration, err = time.ParseDuration(toParse)
	return
}

func (ttl *TTL) Scan(value any) error {
	if value == nil {
		return nil
	}

	var src string
	var ok bool
	if src, ok = value.(string); !ok {
		if err := json.Unmarshal(value.([]byte), &src); err != nil {
			return fmt.Errorf("could not decode ttl as json %s: %s", value, err)
		}
	}

	if value == "" {
		return nil
	}

	ttl.src = src

	if err := ttl.Parse(); err != nil {
		return err
	}

	return nil
}

func (ttl *TTL) UnmarshalJSON(value []byte) error {
	if err := json.Unmarshal(value, &ttl.src); err != nil {
		return err
	}
	return ttl.Parse()
}

func (ttl *TTL) MarshalJSON() ([]byte, error) {
	return json.Marshal(ttl.src)
}

func (ttl *TTL) MarshalDB() (any, error) {
	return json.Marshal(ttl.src)
}

func (ttl *TTL) FromNow() time.Time {
	return time.Now().Add(ttl.duration)
}

func (ttl *TTL) Seconds() int {
	return int(ttl.duration)
}

var _ sql.Scanner = &TTL{}
var _ db.Marshaler = &TTL{}
var _ json.Marshaler = &TTL{}
var _ json.Unmarshaler = &TTL{}
